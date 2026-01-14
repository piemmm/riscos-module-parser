use strict;
use warnings;
use Fcntl qw(SEEK_SET);

# Returns:
#   (0, undef) -> not likely a module
#   (1, \%info)-> likely module; info includes title/version/help/swis/command_table/bitness
sub riscos_module_info {
    my ($path) = @_;
    return (0, undef) unless defined $path && -f $path;

    open my $fh, '<:raw', $path or return (0, undef);
    my $size = -s $fh;
    return (0, undef) unless defined $size && $size >= 28;  # at least 7 words

    # Read enough header words if present:
    #  7 words  = 28 bytes (minimum legacy header)
    # 11 words  = 44 bytes (through SWI decoder field)
    # 12 words  = 48 bytes (includes messages filename field)
    # 13 words  = 52 bytes (includes module feature flags field)
    my $want =
          ($size >= 52) ? 52
        : ($size >= 48) ? 48
        : ($size >= 44) ? 44
        :                28;

    my $hdr = '';
    my $n = read($fh, $hdr, $want);
    return (0, undef) unless defined $n && $n == $want;

    my @w = unpack('V*', $hdr); # little-endian u32 words
    return (0, undef) unless @w >= 7;

    my ($w_start, $w_init, $w_final, $w_svc,
        $off_title, $off_help, $off_cmdtbl) = @w[0..6];

    # -------- helpers --------
    my $read_bytes = sub {
        my ($off, $len) = @_;
        return undef if !defined $off || $off < 0 || $len < 0 || $off + $len > $size;
        seek($fh, $off, SEEK_SET) or return undef;
        my $buf = '';
        my $got = read($fh, $buf, $len);
        return undef unless defined $got && $got == $len;
        return $buf;
    };

    my $read_cstr = sub {
        my ($off, $max) = @_;
        return undef if !defined $off || $off <= 0 || $off >= $size;
        $max = 2048 unless defined $max && $max > 0;

        my $len = $max;
        $len = $size - $off if $off + $len > $size;

        seek($fh, $off, SEEK_SET) or return undef;
        my $buf = '';
        my $got = read($fh, $buf, $len);
        return undef unless defined $got && $got > 0;

        my $nul = index($buf, "\0");
        return undef if $nul < 0;

        return substr($buf, 0, $nul);
    };

    my $read_cstr_len = sub {
        my ($off, $max) = @_;
        return (undef, 0) if !defined $off || $off < 0 || $off >= $size;
        $max = 256 unless defined $max && $max > 0;

        my $len = $max;
        $len = $size - $off if $off + $len > $size;

        seek($fh, $off, SEEK_SET) or return (undef, 0);
        my $buf = '';
        my $got = read($fh, $buf, $len);
        return (undef, 0) unless defined $got && $got > 0;

        my $nul = index($buf, "\0");
        return (undef, 0) if $nul < 0;

        my $s = substr($buf, 0, $nul);
        return ($s, $nul + 1); # consumed including NUL
    };

    my $is_aligned_off = sub {
        my ($off) = @_;
        return 1 if $off == 0;
        return 0 if ($off & 3) != 0;
        return 0 if $off >= $size;
        return 1;
    };

    my $is_unaligned_off = sub {
        my ($off) = @_;
        return 1 if $off == 0;
        return 0 if $off >= $size;
        return 1;
    };

    # -------- core header validation (heuristic but strict) --------

    # Start word: if it looks like an offset (bits 31-25 and 1-0 clear) it must be aligned+in-range.
    my $start_looks_offset = (($w_start & 0xFE000003) == 0);
    if ($start_looks_offset) {
        return (0, undef) unless $is_aligned_off->($w_start);
    }

    # Init word: top bits are flags; low 30 bits are offset/length; must be word-aligned
    my $init_compressed = ($w_init & 0x80000000) != 0;
    my $init_val        =  $w_init & 0x3FFFFFFF;
    return (0, undef) if ($init_val & 3) != 0;

    if ($init_compressed) {
        # When compressed, init_val is (aligned) length of compressed module
        return (0, undef) unless $init_val >= 28 && $init_val <= $size;
    } else {
        return (0, undef) unless ($init_val == 0) || $is_aligned_off->($init_val);
    }

    # Final word: bit 31 is a flag; remaining bits are an aligned offset
    my $final_off = $w_final & 0x7FFFFFFF;
    return (0, undef) unless ($final_off == 0) || $is_aligned_off->($final_off);

    # Service handler: aligned offset or zero
    return (0, undef) unless $is_aligned_off->($w_svc);

    # Title offset must exist and be in-file
    return (0, undef) unless $off_title && $is_unaligned_off->($off_title);

    # Help offset optional (but if present must be valid)
    return (0, undef) unless $is_unaligned_off->($off_help);

    # Command table offset optional (but if present must be valid)
    return (0, undef) unless $is_unaligned_off->($off_cmdtbl);

    my $title = $read_cstr->($off_title, 256) or return (0, undef);
    return (0, undef) if length($title) == 0 || length($title) > 128;

    # Allow ASCII + Latin-1 (excluding C0/C1 controls)
    return (0, undef) if $title =~ /[^\x20-\x7E\xA0-\xFF]/;

    my $help;
    if ($off_help) {
        $help = $read_cstr->($off_help, 4096);
        return (0, undef) unless defined $help;   # offset non-zero but no string => reject
    }

    # Require at least *something* that implies functionality, to reduce false positives.
    my $has_any_entry =
        (!$start_looks_offset ? 1 : ($w_start != 0)) ||
        ($init_compressed ? 1 : ($init_val != 0)) ||
        ($final_off != 0) ||
        ($w_svc != 0) ||
        ($off_cmdtbl != 0);

    return (0, undef) unless $has_any_entry;

    # Best-effort version parse (often from help string)
    my $version;
    if (defined $help && length $help) {
        if ($help =~ /^\Q$title\E(?:[ \t]+)v?([0-9]+(?:\.[0-9]+)+(?:[A-Za-z0-9]*)?)/) {
            $version = $1;
        } elsif ($help =~ /\bv?([0-9]+(?:\.[0-9]+)+(?:[A-Za-z0-9]*)?)\b/) {
            $version = $1;
        }
    }

    my %info = (
        title   => $title,
        help    => $help,      # may be undef
        version => $version,   # may be undef

        bitness       => 26,
        is_32bit_safe => 0,

        swis          => [],
        command_table => [],
    );

    # Figure out which optional header regions are plausibly present (avoid overlap with title string)
    my $has_swi_header  = (@w >= 11 && $off_title >= 44) ? 1 : 0; # words 7..10
    my $has_msg_header  = (@w >= 12 && $off_title >= 48) ? 1 : 0; # word 11
    my $has_full_header = (@w >= 13 && $off_title >= 52) ? 1 : 0; # word 12

    # Optional messages file name (if present)
    if ($has_msg_header) {
        my $msg_off = $w[11];
        if ($msg_off) {
            # PRM says message filename string must be word-aligned
            if ( ($msg_off & 3) == 0 ) {
                my $msg = $read_cstr->($msg_off, 512);
                $info{messages_file} = $msg if defined $msg;
            }
        }
    }

    # -------- 26-bit vs 32-bit (via feature flags word if present) --------
    if ($has_full_header) {
        my $flags_off = $w[12];  # offset to module feature flags word
        $info{feature_flags_offset} = $flags_off;

        if ($flags_off && ($flags_off & 3) == 0 && $flags_off + 4 <= $size) {
            my $fb = $read_bytes->($flags_off, 4);
            if (defined $fb) {
                my $flags = unpack('V', $fb);
                $info{feature_flags_word} = sprintf("0x%08X", $flags);

                # Bit 0 indicates 32-bit-safe interface
                if ($flags & 0x1) {
                    $info{bitness}       = 32;
                    $info{is_32bit_safe} = 1;
                }
            }
        }
        # else: leave defaults (26-bit, not 32-bit-safe)
    }

    # -------- SWI names (best-effort) --------
    if ($has_swi_header) {
        my $chunk_base      = $w[7];  # base SWI number for the 64-SWI chunk
        my $swi_handler_off = $w[8];
        my $swi_names_off   = $w[9];
        my $swi_decoder_off = $w[10];

        if ($chunk_base
            && $chunk_base <= 0x00FFFFFF
            && ($chunk_base % 64) == 0
            && (!$swi_handler_off || $is_aligned_off->($swi_handler_off))
            && (!$swi_decoder_off || $is_aligned_off->($swi_decoder_off))
            && (!$swi_names_off   || $is_unaligned_off->($swi_names_off)))
        {
            $info{swi_chunk_base} = $chunk_base;

            if ($swi_names_off) {
                my $max = $size - $swi_names_off;
                $max = 65536 if $max > 65536;

                seek($fh, $swi_names_off, SEEK_SET) or goto SKIP_SWI_NAMES;
                my $buf = '';
                read($fh, $buf, $max);

                my $end = index($buf, "\0\0");  # terminator
                if ($end >= 0) {
                    $buf = substr($buf, 0, $end + 2);
                    my @parts = split(/\0/, $buf, -1);

                    my $prefix = shift @parts;
                    if (defined $prefix && length $prefix) {
                        $info{swi_prefix} = $prefix;

                        my @swis;
                        for (my $i = 0; $i < @parts && $i < 64; $i++) {
                            my $nm = $parts[$i];
                            last if !defined $nm || $nm eq '';

                            my $full =
                                ($prefix =~ /_$/) ? ($prefix . $nm)
                                                  : ($prefix . '_' . $nm);

                            push @swis, {
                                name   => $full,
                                number => $chunk_base + $i,
                            };
                        }
                        $info{swis} = \@swis;
                    }
                }
            }
        }
    }
SKIP_SWI_NAMES:

    # -------- Command keyword table parsing (best-effort) --------
    if ($off_cmdtbl) {
        my @entries;
        my $pos = $off_cmdtbl;

        my $max_entries = 512;   # safety bound
        for (my $idx = 0; $idx < $max_entries; $idx++) {
            last if $pos >= $size;

            my ($kw, $consumed) = $read_cstr_len->($pos, 512);
            if (!defined $kw) {
                $info{command_table_error} = "Failed reading keyword string at offset $pos";
                last;
            }

            # Table terminated by a zero byte (i.e. empty string entry)
            last if $kw eq '';

            $pos += $consumed;

            # ALIGN to word boundary
            $pos = ($pos + 3) & ~3;

            # Need 4 words following: code_off, info_word, invalid_off, help_off
            if ($pos + 16 > $size) {
                $info{command_table_error} = "Truncated command entry after '$kw'";
                last;
            }

            my $block = $read_bytes->($pos, 16);
            if (!defined $block) {
                $info{command_table_error} = "Failed reading command entry metadata for '$kw'";
                last;
            }
            my ($code_off, $info_word, $inv_off, $help_off2) = unpack('V4', $block);
            $pos += 16;

            # Decode info word bytes
            my $min_params    =  $info_word        & 0xFF;
            my $gstrans_mask  = ($info_word >> 8)  & 0xFF;  # first 8 params
            my $max_params    = ($info_word >> 16) & 0xFF;

            # Decode flag bits (top byte); includes message-token flag in later systems
            my $is_fs_command      = ($info_word & 0x80000000) ? 1 : 0; # bit 31
            my $is_status_config   = ($info_word & 0x40000000) ? 1 : 0; # bit 30
            my $help_is_code       = ($info_word & 0x20000000) ? 1 : 0; # bit 29
            my $strings_are_tokens = ($info_word & 0x10000000) ? 1 : 0; # bit 28 (message-file tokens)

            # Validate offsets we can sanity-check
            if ($code_off && ($code_off & 3)) {
                $info{command_table_error} = "Unaligned code offset for '$kw'";
                last;
            }
            if ($code_off && $code_off >= $size) {
                $info{command_table_error} = "Code offset outside file for '$kw'";
                last;
            }
            if ($inv_off && $inv_off >= $size) {
                $info{command_table_error} = "Invalid-syntax offset outside file for '$kw'";
                last;
            }
            if ($help_off2 && $help_off2 >= $size) {
                $info{command_table_error} = "Help offset outside file for '$kw'";
                last;
            }

            # Read strings (or tokens) if present and applicable
            my $invalid_syntax;
            if ($inv_off) {
                $invalid_syntax = $read_cstr->($inv_off, 1024);
                # If it isn't NUL-terminated, keep it as undef rather than failing the whole module.
            }

            my $entry_help;
            my $help_code_off;
            if ($help_off2) {
                if ($help_is_code) {
                    $help_code_off = $help_off2;   # offset to code, not string
                } else {
                    $entry_help = $read_cstr->($help_off2, 4096);
                }
            }

            my $entry_type =
                  $is_status_config ? "status/configure"
                : $is_fs_command    ? "filing-system command"
                : ($code_off ? "command" : "help-only keyword");

            push @entries, {
                keyword => $kw,
                type    => $entry_type,

                code_offset => $code_off, # 0 => no code (help-only)

                info_word_hex   => sprintf("0x%08X", $info_word),
                min_params      => $min_params,
                max_params      => $max_params,
                gstrans_mask    => sprintf("0x%02X", $gstrans_mask),

                is_filing_system_command => $is_fs_command,
                is_status_configure      => $is_status_config,
                help_is_code             => $help_is_code,
                strings_are_message_tokens => $strings_are_tokens,

                invalid_syntax_offset => $inv_off,
                invalid_syntax        => $invalid_syntax,  # may be token if strings_are_message_tokens

                help_offset     => $help_off2,
                help            => $entry_help,            # may be token if strings_are_message_tokens
                help_code_offset => $help_code_off,        # if help_is_code
            };
        }

        $info{command_table} = \@entries;
    }

    return (1, \%info);
}


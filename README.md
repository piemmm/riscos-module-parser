# riscos-module-parser

Information from RISC OS modules

## Description

This is a perl script to extract information from 26 and 32bit RISC OS modules, it will extract, if present,  the command structure, SWI names, if it is 32bit safe, the name, version and help.

## Dependencies

Perl. A computer. You know the rest.

## Usage example


```perl
my ($ok, $m) = riscos_module_info($ARGV[0]);
if (!$ok) {
    print "Not a module\n";
    exit 1;
}

print "Title:   $m->{title}\n";
print "Bitness: $m->{bitness}-bit", ($m->{is_32bit_safe} ? " (32-bit safe)\n" : "\n");
print "Version: ", (defined $m->{version} ? $m->{version} : "(unknown)"), "\n";
print "Help:    ", (defined $m->{help} ? $m->{help} : "(none)"), "\n";

if ($m->{swi_chunk_base}) {
    printf "SWI base: &%X\n", $m->{swi_chunk_base};
}
if ($m->{swis} && @{$m->{swis}}) {
    print "SWIs:\n";
    for my $s (@{$m->{swis}}) {
        printf "  %-40s &%X\n", $s->{name}, $s->{number};
    }
}

if ($m->{command_table} && @{$m->{command_table}}) {
    print "Command keyword table:\n";
    for my $e (@{$m->{command_table}}) {
        printf "  %-20s [%s] code=%s min=%d max=%d\n",
            $e->{keyword},
            $e->{type},
            ($e->{code_offset} ? sprintf("&%X",$e->{code_offset}) : "none"),
            $e->{min_params}, $e->{max_params};
    }
} else {
    print "Command keyword table: (none)\n";
}
if ($m->{command_table_error}) {
    print "Command table parse warning: $m->{command_table_error}\n";
}
```

## Author

Ian Hawkins
 

 

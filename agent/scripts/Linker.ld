LINK_BASE = 0x0000;

ENTRY( Start )

SECTIONS
{
    . = LINK_BASE;
    .text : {
        . = LINK_BASE;
        *( .text$A );
        *( .text$B );
        *( .rdata* );
        FILL( 0x00 )
        . = ALIGN( 0x1000 );
        __Instance_offset = .;https://cobalt-strike.github.io/community_kit/
        *( .global );
        *( .text$E );
        *( .text$P );
    }

    .eh_frame : {
        *( .eh_frame )
    }
}
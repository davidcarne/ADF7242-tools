#!/usr/bin/python3

import argparse

ram_addrs = {
    0x307: "rx_m",
    0x32E: "gp_in",

    0x314: "txpb",
    0x315: "rxpb",
};

func_names = {
    0x10b8: "filter_packet_1",
    0x1129: "filter_packet_addr",
    0x1133: "_filter_packet_addr__not_all",
    0x12a0: "_filter_packet_addr_out_ok",
    0x12f7: "something_set_rx_mode",
    0x1395: "IRQ_set_csma_ca_complete"
}

comm = {
    0x1159: "Check if auto_cfg.is_pan_coord",
    0x112a: "Test if all addrs are allowed",
    0x12d2: "Check auto_ack_framepend",
    0x10f8: "Trig ISR: Allowed frame det during rx"
}

def sym_ram(addr):
    if addr in ram_addrs:
        return ram_addrs[sym]
    return "$%05x" % addr

def sym_func(addr):
    if addr in func_names:
        return func_names[addr]
    return "#%#06x" % addr

def disasm(a, addr):
    b0 = a[0]
    if len(a) > 1:
        b1 = a[1]
    else:
        b1 = 0

    if len(a) > 2:
        b2 = a[2]
    else:
        b2 = 0


    if b0 == 0x00:
        return 2, "x0 %2x" % b1 

    elif b0 == 0x01:
        return 1, "clr r1?"

    elif b0 == 0x05:
        return 1, "x5"

    elif b0 == 0x07:
        return 1, "mov A, r1"

    elif b0 == 0x08:
        return 2, "x8 %02x" % b1

    # 0x0A - ret
    elif b0 == 0x0a:
        return 1, "ret"

    # 0f xx xx
    # AJMP / ACALL
    elif b0 == 0x0f and b1 & 0x80 == 0x80:
        return 3, "ajmp %s" % sym_func((a[1] << 8  | a[2]) & 0x7FFF)
    elif b0 == 0x0f and b1 & 0x80 == 0x00:
        return 3, "acall %s" % sym_func((a[1] << 8  | a[2]) & 0x7FFF)

    # 1x - MOV reg, imm
    elif b0 & 0xF0 == 0x10 and (b0 & 0xC) in (4,8):
        rno = (b0 & 0xC) >> 2
        rval = (b0 & 0x3) << 8 |b1
        return 2, "mov r%d, %#5x" % (rno, rval)

    elif b0 & 0xF0 == 0x10 and (b0 & 0xC) in (0xC,):
        rval = b1
        assert (b0 & 0x3) == 0
        return 2, "cmp A, #%#5x" % (rval)


    elif b0 == 0x6e:
        return 1, "x6e"

    # Ax / Bx (rel/conf jump)
    elif b0 in (0xa5, 0xa6, 0xa7, 0xa8, 0xaa, 0xaf, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba):
        code = ".?(%02x)"%b0
        if b0 == 0xaf:
            code = ".always"
        elif b0 == 0xb7:
            code = ".nz/nb2"
        elif b0 == 0xba:
            code = ".?/nb1"
        elif b0 == 0xb8:
            code = ".?/nb0"
        elif b0 == 0xb9:
            code = ".?/nb3"
        elif b0 == 0xa7:
            code = ".z/b2"
        elif b0 == 0xaa:
            code = ".?/b1"
        elif b0 == 0xa8:
            code = ".?/b0"
        elif b0 == 0xa9:
            code = ".?/b3"

        return 2, "rjmp%s %s" % (code, sym_func(0x82 - a[1] + addr))
        
    elif b0 == 0xC0:
        return 1, "and A, r1"



    # Dx shift - exact meaning unknown
    elif b0 & 0xF0 == 0xD0:
        return 1, "shift A, #%x" % (b0 & 0xF)

    # Ex - bit set clear (R1)
    elif b0 & 0xF0 == 0xE0:
        sc = b0 & 0x8
        bit = b0 & 0x7
        return 1, "bsc r1.%d (%d)" % (bit, sc)




    #elif b0 in (0xc0, 0xc2):
    #    return 1, "%02x %02x" %(b0, b1)


    # Fx

    #elif b0 == 0xF0:
    #    return 2, "f0 %2x" % b1
    elif b0 == 0xF6:
        return 1, "mov r1, [r2]"
    elif b0 == 0xF7:
        return 1, "mov [r2], r1"

    # f8/f9 unknown


    # Test high nibble
    elif b0 == 0xFA:
        return 1, "thi"

    # Test low nibble
    elif b0 == 0xFb:
        return 1, "tlo"

    elif b0 == 0xFE:
        return 1, "push r2"
    
    elif b0 == 0xFF:
        return 1, "pop r2"



    return 1, ".db %02x" % a[0]

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("f", type=argparse.FileType("rb"))
    ap.add_argument("-s", action="store_true")
    args = ap.parse_args()


    d = args.f.read()


    i = 0
    while i < len(d):
        n = 0x1000 + i


        if n in func_names or n in comm:
            print ("%04x:" % n)
        if n in func_names:
            print("%04x:            %s" % (n, func_names[n]))

        if n in comm:
            print("%04x:                   ; %s" % (n, comm[n]))

        if n < 0x103d or n >= 0x10b8:
            off, s = disasm(d[i:i+10], n)
        else:
            off, s = 1, ".db %02x" % d[i]
        if not s.startswith(".db") or args.s:
            if " " in s:
                opc, opa = s.split(" ",1)
            else:
                opa = ""
                opc = s

            bs = "".join("%02x " % j for j in d[i:i+off])
            print("%04x: %-9s         %-8s %s" % (n,bs,opc,opa))

        if "jmp" in s or "ret" in s:
            print("%04x:" % n)

        if "ret" in s:
            print("%04x:" % n)

        i += off




if __name__ == "__main__":
    main()

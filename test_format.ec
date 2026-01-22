fn main() {
    let x = 42;
    let y = 255;
    
    // Test combined width+base specs that were previously broken
    print "{:04x}\n", x;      // Should print: 002a
    print "{:08b}\n", x;      // Should print: 00101010
    print "{:08o}\n", x;      // Should print: 00000052
    print "{:06X}\n", y;      // Should print: 0000FF
    
    // Test other combinations
    print "{:6d}\n", x;       // Should print: "    42" (space-padded)
    print "{:06d}\n", x;      // Should print: "000042" (zero-padded)
}

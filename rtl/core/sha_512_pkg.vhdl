--MIT License
--
--Copyright (c) 2017  Danny Savory
--
--Permission is hereby granted, free of charge, to any person obtaining a copy
--of this software and associated documentation files (the "Software"), to deal
--in the Software without restriction, including without limitation the rights
--to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
--copies of the Software, and to permit persons to whom the Software is
--furnished to do so, subject to the following conditions:
--
--The above copyright notice and this permission notice shall be included in all
--copies or substantial portions of the Software.
--
--THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
--IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
--FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
--AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
--LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
--OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
--SOFTWARE.


-- ############################################################################
--  The official specifications of the SHA-256 algorithm can be found here:
--      http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf


library ieee;
use ieee.std_logic_1164.all;
use ieee.numeric_std.all;

package sha_512_pkg is
    constant WORD_SIZE : natural := 64; --SHA-512 uses 64-bit words
    
    --array types for SHA-512
    type K_DATA is array (0 to 79) of std_logic_vector(WORD_SIZE-1 downto 0);
    type M_DATA is array (0 to 15) of std_logic_vector(WORD_SIZE-1 downto 0);
    type H_DATA is array (0 to 7) of std_logic_vector(WORD_SIZE-1 downto 0);
    
    --Message blocks, the padded message should be a multiple of 512 bits,
    signal M : M_DATA;
    
    --function definitions
    function ROTR (a : std_logic_vector(WORD_SIZE-1 downto 0); n : natural)
                    return std_logic_vector;
    function ROTL (a : std_logic_vector(WORD_SIZE-1 downto 0); n : natural)
                    return std_logic_vector;
    function SHR (a : std_logic_vector(WORD_SIZE-1 downto 0); n : natural)
                    return std_logic_vector;
    function CH (x : std_logic_vector(WORD_SIZE-1 downto 0);
                    y : std_logic_vector(WORD_SIZE-1 downto 0);
                    z : std_logic_vector(WORD_SIZE-1 downto 0))
                    return std_logic_vector;
    function MAJ (x : std_logic_vector(WORD_SIZE-1 downto 0);
                    y : std_logic_vector(WORD_SIZE-1 downto 0);
                    z : std_logic_vector(WORD_SIZE-1 downto 0))
                    return std_logic_vector;
                    
    function SIGMA_UCASE_0 (x : std_logic_vector(WORD_SIZE-1 downto 0))
                    return std_logic_vector;
    function SIGMA_UCASE_1 (x : std_logic_vector(WORD_SIZE-1 downto 0))
                    return std_logic_vector;
    function SIGMA_LCASE_0 (x : std_logic_vector(WORD_SIZE-1 downto 0))
                    return std_logic_vector;
    function SIGMA_LCASE_1 (x : std_logic_vector(WORD_SIZE-1 downto 0))
                    return std_logic_vector;

    component sha_512_core
    generic(
        RESET_VALUE : std_logic := '0'    --reset enable value
    );
    port(
        clk : in std_logic;
        rst : in std_logic;
        data_ready : in std_logic;  --the edge of this signal triggers the capturing of input data and hashing it.
        n_blocks : in natural; --N, the number of (padded) message blocks
        msg_block_in : in std_logic_vector(0 to (16 * WORD_SIZE)-1);
        --mode_in : in std_logic;
        finished : out std_logic;
        data_out : out std_logic_vector((WORD_SIZE * 8)-1 downto 0) --SHA-512 results in a 512-bit hash value
    );
    end component;

end package;

package body sha_512_pkg is
    function ROTR (a : std_logic_vector(WORD_SIZE-1 downto 0); n : natural)
                    return std_logic_vector is
        --result : std_logic_vector(WORD_SIZE-1 downto 0);
    begin
        --signal result : std_logic_vector(WORD_SIZE-1 downto 0);
        return (std_logic_vector(shift_right(unsigned(a), n))) or std_logic_vector((shift_left(unsigned(a), (WORD_SIZE-n))));
    end function;
    
    function ROTL (a : std_logic_vector(WORD_SIZE-1 downto 0); n : natural)
                    return std_logic_vector is
        --result : std_logic_vector(WORD_SIZE-1 downto 0);
    begin
        --signal result : std_logic_vector(WORD_SIZE-1 downto 0);
        return (std_logic_vector(shift_left(unsigned(a), n))) or std_logic_vector((shift_right(unsigned(a), (WORD_SIZE-n))));
    end function;
    
    function SHR (a : std_logic_vector(WORD_SIZE-1 downto 0); n : natural)
                    return std_logic_vector is
    begin
        return std_logic_vector(shift_right(unsigned(a), n));
    end function;
    
    function CH (x : std_logic_vector(WORD_SIZE-1 downto 0);
                    y : std_logic_vector(WORD_SIZE-1 downto 0);
                    z : std_logic_vector(WORD_SIZE-1 downto 0))
                    return std_logic_vector is
    begin
        return (x and y) xor (not(x) and z);
    end function;
    
    function MAJ (x : std_logic_vector(WORD_SIZE-1 downto 0);
                    y : std_logic_vector(WORD_SIZE-1 downto 0);
                    z : std_logic_vector(WORD_SIZE-1 downto 0))
                    return std_logic_vector is
    begin
        return (x and y) xor (x and z) xor (y and z);
    end function;
    
    function SIGMA_UCASE_0 (x : std_logic_vector(WORD_SIZE-1 downto 0))
                    return std_logic_vector is
    begin
        return ROTR(x, 28) xor ROTR(x, 34) xor ROTR(x, 39);
    end function;
    
    function SIGMA_UCASE_1 (x : std_logic_vector(WORD_SIZE-1 downto 0))
                    return std_logic_vector is
    begin
        return ROTR(x, 14) xor ROTR(x, 18) xor ROTR(x, 41);
    end function;
    
    function SIGMA_LCASE_0 (x : std_logic_vector(WORD_SIZE-1 downto 0))
                    return std_logic_vector is
    begin
        return ROTR(x, 1) xor ROTR(x, 8) xor SHR(x, 7);
    end function;
    
    function SIGMA_LCASE_1 (x : std_logic_vector(WORD_SIZE-1 downto 0))
                    return std_logic_vector is
    begin
        return ROTR(x, 19) xor ROTR(x, 61) xor SHR(x, 6);
    end function;
    
end package body;


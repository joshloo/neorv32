-- #################################################################################################
-- # << NEORV32 - Custom Functions Subsystem (CFS) >>                                              #
-- # ********************************************************************************************* #
-- # For tightly-coupled custom co-processors. Provides 32x32-bit memory-mapped registers.         #
-- # This is just an "example/illustrating template". Modify this file to implement your custom    #
-- # design logic.                                                                                 #
-- # ********************************************************************************************* #
-- # BSD 3-Clause License                                                                          #
-- #                                                                                               #
-- # Copyright (c) 2021, Stephan Nolting. All rights reserved.                                     #
-- #                                                                                               #
-- # Redistribution and use in source and binary forms, with or without modification, are          #
-- # permitted provided that the following conditions are met:                                     #
-- #                                                                                               #
-- # 1. Redistributions of source code must retain the above copyright notice, this list of        #
-- #    conditions and the following disclaimer.                                                   #
-- #                                                                                               #
-- # 2. Redistributions in binary form must reproduce the above copyright notice, this list of     #
-- #    conditions and the following disclaimer in the documentation and/or other materials        #
-- #    provided with the distribution.                                                            #
-- #                                                                                               #
-- # 3. Neither the name of the copyright holder nor the names of its contributors may be used to  #
-- #    endorse or promote products derived from this software without specific prior written      #
-- #    permission.                                                                                #
-- #                                                                                               #
-- # THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS   #
-- # OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF               #
-- # MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE    #
-- # COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,     #
-- # EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE #
-- # GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED    #
-- # AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING     #
-- # NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED  #
-- # OF THE POSSIBILITY OF SUCH DAMAGE.                                                            #
-- # ********************************************************************************************* #
-- # The NEORV32 Processor - https://github.com/stnolting/neorv32              (c) Stephan Nolting #
-- #################################################################################################

library ieee;
use ieee.std_logic_1164.all;
use ieee.numeric_std.all;
use ieee.std_logic_unsigned.all;

library neorv32;
use neorv32.neorv32_package.all;

entity neorv32_cfs is
  generic (
    CFS_CONFIG   : std_ulogic_vector(31 downto 0); -- custom CFS configuration generic
    CFS_IN_SIZE  : positive := 512; -- size of CFS input conduit in bits , this is now used as SHA5 result
    CFS_OUT_SIZE : positive := 32  -- size of CFS output conduit in bits
  );
  port (
    -- host access --
    clk_i       : in  std_ulogic; -- global clock line
    rstn_i      : in  std_ulogic; -- global reset line, low-active, use as async
    addr_i      : in  std_ulogic_vector(31 downto 0); -- address
    rden_i      : in  std_ulogic; -- read enable
    wren_i      : in  std_ulogic; -- word write enable
    data_i      : in  std_ulogic_vector(31 downto 0); -- data in
    data_o      : out std_ulogic_vector(31 downto 0); -- data out
    ack_o       : out std_ulogic; -- transfer acknowledge
    -- clock generator --
    clkgen_en_o : out std_ulogic; -- enable clock generator
    clkgen_i    : in  std_ulogic_vector(07 downto 0); -- "clock" inputs
    -- CPU state --
    sleep_i     : in  std_ulogic; -- set if cpu is in sleep mode
    -- interrupt --
    irq_o       : out std_ulogic; -- interrupt request
    irq_ack_i   : in  std_ulogic; -- interrupt acknowledge
    -- custom io (conduits) --
    cfs_s5_done : in  std_ulogic;
    cfs_in_i    : in  std_ulogic_vector(CFS_IN_SIZE-1 downto 0);  -- custom inputs
    cfs_out_o   : out std_ulogic_vector(CFS_OUT_SIZE-1 downto 0)  -- custom outputs
  );
end neorv32_cfs;

architecture neorv32_cfs_rtl of neorv32_cfs is

  -- IO space: module base address (DO NOT MODIFY!) --
  constant hi_abb_c : natural := index_size_f(io_size_c)-1; -- high address boundary bit
  constant lo_abb_c : natural := index_size_f(cfs_size_c); -- low address boundary bit

  -- access control --
  signal acc_en : std_ulogic; -- module access enable
  signal addr   : std_ulogic_vector(31 downto 0); -- access address
  signal wren   : std_ulogic; -- word write enable
  signal rden   : std_ulogic; -- read enable

  -- default CFS interface registers --
  type cfs_regs_t is array (0 to 20) of std_ulogic_vector(31 downto 0); -- extend to 20 members
  signal cfs_reg_wr : cfs_regs_t; -- interface registers for WRITE accesses
  signal cfs_reg_rd : cfs_regs_t; -- interface registers for READ accesses

begin

  -- Access Control -------------------------------------------------------------------------
  -- -------------------------------------------------------------------------------------------
  -- These assignments are required to check if the CFS is accessed at all.
  -- DO NOT MODIFY this unless you really know what you are doing.
  acc_en <= '1' when (addr_i(hi_abb_c downto lo_abb_c) = cfs_base_c(hi_abb_c downto lo_abb_c)) else '0';
  addr   <= cfs_base_c(31 downto lo_abb_c) & addr_i(lo_abb_c-1 downto 2) & "00"; -- word aligned
  wren   <= acc_en and wren_i; -- full 32-bit word write enable
  rden   <= acc_en and rden_i; -- the read access is always a full 32-bit word wide; if required, the byte/half-word select/masking is done in the CPU


  -- CFS Generics ---------------------------------------------------------------------------
  -- -------------------------------------------------------------------------------------------
  -- In its default version, the CFS provides the configuration generics. single generic:
  -- CFS_IN_SIZE configures the size (in bits) of the CFS input conduit cfs_in_i
  -- CFS_OUT_SIZE configures the size (in bits) of the CFS output conduit cfs_out_o
  -- CFS_CONFIG is a blank 32-bit generic. It is intended as a "generic conduit" to propagate custom configuration flags from the top entity down to this entiy.


  -- CFS IOs --------------------------------------------------------------------------------
  -- -------------------------------------------------------------------------------------------
  -- By default, the CFS provides two IO signals (cfs_in_i and cfs_out_o) that are available at the processor top entity.
  -- These are intended as "conduits" to propagate custom signals this entity <=> processor top entity.

  cfs_out_o <= (others => '0'); -- not used for this minimal example


  -- Reset System ---------------------------------------------------------------------------
  -- -------------------------------------------------------------------------------------------
  -- The CFS can be reset using the global rstn_i signal. This signal should be used as asynchronous reset and is active-low.
  -- Note that rstn_i can be asserted by an external reset and also by a watchdog-cause reset.
  --
  -- Most default peripheral devices of the NEORV32 do NOT use a dedicated reset at all. Instead, these units are reset by writing ZERO
  -- to a specific "control register" located right at the beginning of the devices's address space (so this register is cleared at first).
  -- The crt0 start-up code write ZERO to every single address in the processor's IO space - including the CFS.
  -- Make sure that this clearing does not cause any unintended actions in the CFS.


  -- Clock System ---------------------------------------------------------------------------
  -- -------------------------------------------------------------------------------------------
  -- The processor top unit implements a clock generator providing 8 "derived clocks"
  -- Actually, these signals should not be used as direct clock signals, but as *clock enable* signals.
  -- clkgen_i is always synchronous to the main system clock (clk_i).
  --
  -- The following clock divider rates are available:
  -- clkgen_i(clk_div2_c)    -> MAIN_CLK/2
  -- clkgen_i(clk_div4_c)    -> MAIN_CLK/4
  -- clkgen_i(clk_div8_c)    -> MAIN_CLK/8
  -- clkgen_i(clk_div64_c)   -> MAIN_CLK/64
  -- clkgen_i(clk_div128_c)  -> MAIN_CLK/128
  -- clkgen_i(clk_div1024_c) -> MAIN_CLK/1024
  -- clkgen_i(clk_div2048_c) -> MAIN_CLK/2048
  -- clkgen_i(clk_div4096_c) -> MAIN_CLK/4096
  --
  -- For instance, if you want to drive a clock process at MAIN_CLK/8 clock speed you can use the following construct:
  --
  --   if (rstn_i = '0') then -- async and low-active reset (if required at all)
  --   ...
  --   elsif rising_edge(clk_i) then -- always use the main clock for all clock processes!
  --     if (clkgen_i(clk_div8_c) = '1') then -- the div8 "clock" is actually a clock enable
  --       ...
  --     end if;
  --   end if;
  --
  -- The clkgen_i input clocks are available when at least one IO/peripheral device (for example the UART) requires the clocks generated by the
  -- clock generator. The CFS can enable the clock generator by itself by setting the clkgen_en_o signal high.
  -- The CFS cannot ensure to deactive the clock generator by setting the clkgen_en_o signal low as other peripherals might still keep the generator activated.
  -- Make sure to deactivate the CFS's clkgen_en_o if no clocks are required in here to reduce dynamic power consumption.

  clkgen_en_o <= '0'; -- not used for this minimal example


  -- Further Power Optimization -------------------------------------------------------------
  -- -------------------------------------------------------------------------------------------
  -- The CFS can decide to go into low-power mode (by disabling all switching activity) when the CPU enters sleep mode.
  -- The sleep_i signal is high when the CPU is in sleep mode. Any interrupt including the CFS's irq_o interrupt request signal
  -- will wake up the CPU again.


  -- Interrupt ------------------------------------------------------------------------------
  -- -------------------------------------------------------------------------------------------
  -- The CFS features a single interrupt signal. This interrupt is connected to the CPU's "fast interrupt" channel 1.
  -- Note that this fast interrupt channel is shared with the GPIO pin-change interrupt. Make sure to disable the GPIO's pin-change interrupt
  -- via the according control register if you want to use this interrupt exclusively for the CFS.
  --
  -- The interrupt is single-shot. Setting the irq_o signal high for one cycle will generate an interrupt request.
  -- The interrupt is acknowledged by the CPU via the one-shot irq_ack_i signal indicating that the according interrupt handler is starting.

  irq_o <= '0'; -- not used for this minimal example


  -- Read/Write Access ----------------------------------------------------------------------
  -- -------------------------------------------------------------------------------------------
  -- Here we are reading/writing from/to the interface registers of the module. Please note that the peripheral/IO
  -- modules of the NEORV32 can only be written in full word mode (32-bit). Any other write access (half-word or byte)
  -- will trigger a store bus access fault exception.
  --
  -- The CFS provides up to 32 memory-mapped 32-bit interface register. For instance, these could be used to provide
  -- a <control register> for global control of the unit, a <data register> for reading/writing from/to a data FIFO, a <command register>
  -- for issueing commands and a <status register> for status information.
  --
  -- Following the interface protocol, each read or write access has to be acknowledged in the following cycle using the ack_o signal (or even later
  -- if the module needs additional time; the maximumx latency until an unacknwoledged access will trigger a bus exception is defined via the package's
  -- gloabl "bus_timeout_c" constant). If no ACK is generated, the bus access will time out and cause a store bus access fault exception.

  -- Host access: Read and write access to the interface registers + bus transfer acknowledge.
  -- This example only implements four physical r/w register (the four lowest CF register). The remaining addresses of the CFS are not
  -- associated with any writable or readable register - an access to those is simply ignored but still acknowledged.

  host_access: process(clk_i)
  begin
    if rising_edge(clk_i) then -- synchronous interface for reads and writes
      -- transfer/access acknowledge --
      ack_o <= rden or wren; -- default: required for the CPU to check the CFS is answering a bus read OR write request; all r/w accesses (to any cfs_reg) will succeed
--    ack_o <= rden; -- use this construct if your CFS is read-only
--    ack_o <= wren; -- use this construct if your CFS is write-only
--    ack_o <= ... -- or define the ACK by yourself (example: some registers are read-only, some others can only be written, ...)

      -- write access --
      for i in 0 to 3 loop
        if (wren = '1') then -- word-wide write-access only!
          case addr is -- make sure to use the internal 'addr' signal for the read/write interface
            when cfs_reg0_addr_c => cfs_reg_wr(0) <= data_i; -- for example: control register
            when cfs_reg1_addr_c => cfs_reg_wr(1) <= data_i; -- for example: data in/out fifo
            when cfs_reg2_addr_c => cfs_reg_wr(2) <= data_i; -- for example: command fifo
            when cfs_reg3_addr_c => cfs_reg_wr(3) <= data_i; -- for example: status register
            when cfs_reg4_addr_c => cfs_reg_wr(4) <= data_i; -- for example: control register
            when cfs_reg5_addr_c => cfs_reg_wr(5) <= data_i; -- for example: data in/out fifo
            when cfs_reg6_addr_c => cfs_reg_wr(6) <= data_i; -- for example: command fifo
            when cfs_reg7_addr_c => cfs_reg_wr(7) <= data_i; -- for example: status register
            when cfs_reg8_addr_c => cfs_reg_wr(8) <= data_i; -- for example: control register
            when cfs_reg9_addr_c => cfs_reg_wr(9) <= data_i; -- for example: data in/out fifo
            when cfs_reg10_addr_c => cfs_reg_wr(10) <= data_i; -- for example: command fifo
            when cfs_reg11_addr_c => cfs_reg_wr(11) <= data_i; -- for example: command fifo
            when cfs_reg12_addr_c => cfs_reg_wr(12) <= data_i; -- for example: status register
            when cfs_reg13_addr_c => cfs_reg_wr(13) <= data_i; -- for example: control register
            when cfs_reg14_addr_c => cfs_reg_wr(14) <= data_i; -- for example: data in/out fifo
            when cfs_reg15_addr_c => cfs_reg_wr(15) <= data_i; -- for example: command fifo
            when cfs_reg16_addr_c => cfs_reg_wr(16) <= data_i; -- for example: status register
            when cfs_reg17_addr_c => cfs_reg_wr(17) <= data_i; -- for example: control register
            when cfs_reg18_addr_c => cfs_reg_wr(18) <= data_i; -- for example: data in/out fifo
            when cfs_reg19_addr_c => cfs_reg_wr(19) <= data_i; -- for example: command fifo
            when others          => NULL;
          end case;
        end if;
      end loop; -- i

      -- read access --
      data_o <= (others => '0'); -- the output has to be zero if there is no actual read access
      if (rden = '1') then -- the read access is always a full 32-bit word wide; if required, the byte/half-word select/masking is done in the CPU
        case addr is -- make sure to use the internal 'addr' signal for the read/write interface
          when cfs_reg0_addr_c => data_o <= cfs_reg_rd(0);
          when cfs_reg1_addr_c => data_o <= cfs_reg_rd(1);
          when cfs_reg2_addr_c => data_o <= cfs_reg_rd(2);
          when cfs_reg3_addr_c => data_o <= cfs_reg_rd(3);
          when cfs_reg4_addr_c => data_o <= cfs_reg_rd(4);
          when cfs_reg5_addr_c => data_o <= cfs_reg_rd(5);
          when cfs_reg6_addr_c => data_o <= cfs_reg_rd(6);
          when cfs_reg7_addr_c => data_o <= cfs_reg_rd(7);
          when cfs_reg8_addr_c => data_o <= cfs_reg_rd(8);
          when cfs_reg9_addr_c => data_o <= cfs_reg_rd(9);
          when cfs_reg10_addr_c => data_o <= cfs_reg_rd(10);
          when cfs_reg11_addr_c => data_o <= cfs_reg_rd(11);
          when cfs_reg12_addr_c => data_o <= cfs_reg_rd(12);
          when cfs_reg13_addr_c => data_o <= cfs_reg_rd(13);
          when cfs_reg14_addr_c => data_o <= cfs_reg_rd(14);
          when cfs_reg15_addr_c => data_o <= cfs_reg_rd(15);
          when cfs_reg16_addr_c => data_o <= cfs_reg_rd(16);
          when cfs_reg17_addr_c => data_o <= cfs_reg_rd(17);
          when cfs_reg18_addr_c => data_o <= cfs_reg_rd(18);
          when cfs_reg19_addr_c => data_o <= cfs_reg_rd(19);
          when others          => data_o <= (others => '0'); -- the remaining registers are not implemented and will read as zero
        end case;
      end if;
    end if;
  end process host_access;


  -- CFS Function Core ----------------------------------------------------------------------
  -- -------------------------------------------------------------------------------------------
  -- This is where the actual functionality can be implemented.

  cfs_core: process(cfs_reg_wr, cfs_in_i)
  begin
    cfs_reg_rd(0) <= cfs_reg_wr(0); -- using first 4 as read back scratch pad, potentially use for boot checkpoints
    cfs_reg_rd(1) <= cfs_reg_wr(1);
    cfs_reg_rd(2) <= cfs_reg_wr(2);
    cfs_reg_rd(3)(0) <= cfs_s5_done;
    cfs_reg_rd(3)(30 downto 1) <= (others => '0');
    cfs_reg_rd(3)(31) <= '1';
    cfs_reg_rd(4) <= cfs_in_i(31 downto 0);
    cfs_reg_rd(5) <= cfs_in_i(63 downto 32);
    cfs_reg_rd(6) <= cfs_in_i(95 downto 64);
    cfs_reg_rd(7) <= cfs_in_i(127 downto 96);
    cfs_reg_rd(8) <= cfs_in_i(159 downto 128);
    cfs_reg_rd(9) <= cfs_in_i(191 downto 160);
    cfs_reg_rd(10) <= cfs_in_i(223 downto 192);
    cfs_reg_rd(11) <= cfs_in_i(255 downto 224);
    cfs_reg_rd(12) <= cfs_in_i(287 downto 256);
    cfs_reg_rd(13) <= cfs_in_i(319 downto 288);
    cfs_reg_rd(14) <= cfs_in_i(351 downto 320);
    cfs_reg_rd(15) <= cfs_in_i(383 downto 352);
    cfs_reg_rd(16) <= cfs_in_i(415 downto 384);
    cfs_reg_rd(17) <= cfs_in_i(447 downto 416);
    cfs_reg_rd(18) <= cfs_in_i(479 downto 448);
    cfs_reg_rd(19) <= cfs_in_i(511 downto 480);
  end process cfs_core;


end neorv32_cfs_rtl;

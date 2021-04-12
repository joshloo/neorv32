-- The NEORV32 Processor by Stephan Nolting, https://github.com/stnolting/neorv32
-- Auto-generated memory init file (for BOOTLOADER) from source file <bootloader/main.bin>

library ieee;
use ieee.std_logic_1164.all;

package neorv32_bootloader_image is

  type bootloader_init_image_t is array (0 to 1014) of std_ulogic_vector(31 downto 0);
  constant bootloader_init_image : bootloader_init_image_t := (
    00000000 => x"00000093",
    00000001 => x"00000113",
    00000002 => x"00000193",
    00000003 => x"00000213",
    00000004 => x"00000293",
    00000005 => x"00000313",
    00000006 => x"00000393",
    00000007 => x"00000413",
    00000008 => x"00000493",
    00000009 => x"00000713",
    00000010 => x"00000793",
    00000011 => x"00000517",
    00000012 => x"0cc50513",
    00000013 => x"30551073",
    00000014 => x"34151073",
    00000015 => x"34301073",
    00000016 => x"34201073",
    00000017 => x"30001073",
    00000018 => x"30401073",
    00000019 => x"30601073",
    00000020 => x"ffa00593",
    00000021 => x"32059073",
    00000022 => x"b0001073",
    00000023 => x"b8001073",
    00000024 => x"b0201073",
    00000025 => x"b8201073",
    00000026 => x"80012117",
    00000027 => x"f9410113",
    00000028 => x"ffc17113",
    00000029 => x"00010413",
    00000030 => x"80010197",
    00000031 => x"78818193",
    00000032 => x"f0000593",
    00000033 => x"0005a023",
    00000034 => x"00458593",
    00000035 => x"feb01ce3",
    00000036 => x"80010597",
    00000037 => x"f7058593",
    00000038 => x"80818613",
    00000039 => x"00c5d863",
    00000040 => x"00058023",
    00000041 => x"00158593",
    00000042 => x"ff5ff06f",
    00000043 => x"00001597",
    00000044 => x"f2c58593",
    00000045 => x"80010617",
    00000046 => x"f4c60613",
    00000047 => x"80010697",
    00000048 => x"f4468693",
    00000049 => x"00d65c63",
    00000050 => x"00058703",
    00000051 => x"00e60023",
    00000052 => x"00158593",
    00000053 => x"00160613",
    00000054 => x"fedff06f",
    00000055 => x"00000513",
    00000056 => x"00000593",
    00000057 => x"060000ef",
    00000058 => x"30047073",
    00000059 => x"00000013",
    00000060 => x"10500073",
    00000061 => x"0000006f",
    00000062 => x"ff810113",
    00000063 => x"00812023",
    00000064 => x"00912223",
    00000065 => x"34202473",
    00000066 => x"02044663",
    00000067 => x"34102473",
    00000068 => x"00041483",
    00000069 => x"0034f493",
    00000070 => x"00240413",
    00000071 => x"34141073",
    00000072 => x"00300413",
    00000073 => x"00941863",
    00000074 => x"34102473",
    00000075 => x"00240413",
    00000076 => x"34141073",
    00000077 => x"00012403",
    00000078 => x"00412483",
    00000079 => x"00810113",
    00000080 => x"30200073",
    00000081 => x"800007b7",
    00000082 => x"0007a023",
    00000083 => x"fd010113",
    00000084 => x"8001a223",
    00000085 => x"02812423",
    00000086 => x"fe002403",
    00000087 => x"026267b7",
    00000088 => x"02112623",
    00000089 => x"02912223",
    00000090 => x"03212023",
    00000091 => x"01312e23",
    00000092 => x"01412c23",
    00000093 => x"01512a23",
    00000094 => x"01612823",
    00000095 => x"01712623",
    00000096 => x"01812423",
    00000097 => x"9ff78793",
    00000098 => x"00000613",
    00000099 => x"00000593",
    00000100 => x"00200513",
    00000101 => x"0087f463",
    00000102 => x"00400513",
    00000103 => x"36d000ef",
    00000104 => x"00100513",
    00000105 => x"40d000ef",
    00000106 => x"00005537",
    00000107 => x"00000613",
    00000108 => x"00000593",
    00000109 => x"b0050513",
    00000110 => x"2a9000ef",
    00000111 => x"1c5000ef",
    00000112 => x"00245793",
    00000113 => x"00a78533",
    00000114 => x"00f537b3",
    00000115 => x"00b785b3",
    00000116 => x"1dd000ef",
    00000117 => x"ffff07b7",
    00000118 => x"4d478793",
    00000119 => x"30579073",
    00000120 => x"08000793",
    00000121 => x"30479073",
    00000122 => x"30046073",
    00000123 => x"00000013",
    00000124 => x"00000013",
    00000125 => x"ffff1537",
    00000126 => x"eec50513",
    00000127 => x"309000ef",
    00000128 => x"f1302573",
    00000129 => x"260000ef",
    00000130 => x"ffff1537",
    00000131 => x"f2450513",
    00000132 => x"2f5000ef",
    00000133 => x"fe002503",
    00000134 => x"24c000ef",
    00000135 => x"ffff1537",
    00000136 => x"f2c50513",
    00000137 => x"2e1000ef",
    00000138 => x"fe402503",
    00000139 => x"238000ef",
    00000140 => x"ffff1537",
    00000141 => x"f3450513",
    00000142 => x"2cd000ef",
    00000143 => x"30102573",
    00000144 => x"224000ef",
    00000145 => x"ffff1537",
    00000146 => x"f3c50513",
    00000147 => x"2b9000ef",
    00000148 => x"fc002573",
    00000149 => x"210000ef",
    00000150 => x"ffff1537",
    00000151 => x"f4450513",
    00000152 => x"2a5000ef",
    00000153 => x"fe802503",
    00000154 => x"ffff14b7",
    00000155 => x"00341413",
    00000156 => x"1f4000ef",
    00000157 => x"ffff1537",
    00000158 => x"f4c50513",
    00000159 => x"289000ef",
    00000160 => x"ff802503",
    00000161 => x"1e0000ef",
    00000162 => x"f5448513",
    00000163 => x"279000ef",
    00000164 => x"ff002503",
    00000165 => x"1d0000ef",
    00000166 => x"ffff1537",
    00000167 => x"f6050513",
    00000168 => x"265000ef",
    00000169 => x"ffc02503",
    00000170 => x"1bc000ef",
    00000171 => x"f5448513",
    00000172 => x"255000ef",
    00000173 => x"ff402503",
    00000174 => x"1ac000ef",
    00000175 => x"ffff1537",
    00000176 => x"f6850513",
    00000177 => x"241000ef",
    00000178 => x"0b9000ef",
    00000179 => x"00a404b3",
    00000180 => x"0084b433",
    00000181 => x"00b40433",
    00000182 => x"1d1000ef",
    00000183 => x"02050263",
    00000184 => x"ffff1537",
    00000185 => x"f9450513",
    00000186 => x"21d000ef",
    00000187 => x"0d9000ef",
    00000188 => x"02300793",
    00000189 => x"02f51263",
    00000190 => x"00000513",
    00000191 => x"0180006f",
    00000192 => x"081000ef",
    00000193 => x"fc85eae3",
    00000194 => x"00b41463",
    00000195 => x"fc9566e3",
    00000196 => x"00100513",
    00000197 => x"5dc000ef",
    00000198 => x"0b4000ef",
    00000199 => x"ffff1937",
    00000200 => x"ffff19b7",
    00000201 => x"02300a13",
    00000202 => x"07200a93",
    00000203 => x"06800b13",
    00000204 => x"07500b93",
    00000205 => x"ffff14b7",
    00000206 => x"ffff1c37",
    00000207 => x"fa090513",
    00000208 => x"1c5000ef",
    00000209 => x"155000ef",
    00000210 => x"00050413",
    00000211 => x"129000ef",
    00000212 => x"ea498513",
    00000213 => x"1b1000ef",
    00000214 => x"fb4400e3",
    00000215 => x"01541863",
    00000216 => x"ffff02b7",
    00000217 => x"00028067",
    00000218 => x"fd5ff06f",
    00000219 => x"01641663",
    00000220 => x"05c000ef",
    00000221 => x"fc9ff06f",
    00000222 => x"00000513",
    00000223 => x"03740063",
    00000224 => x"07300793",
    00000225 => x"00f41663",
    00000226 => x"67c000ef",
    00000227 => x"fb1ff06f",
    00000228 => x"06c00793",
    00000229 => x"00f41863",
    00000230 => x"00100513",
    00000231 => x"3fc000ef",
    00000232 => x"f9dff06f",
    00000233 => x"06500793",
    00000234 => x"00f41663",
    00000235 => x"02c000ef",
    00000236 => x"f8dff06f",
    00000237 => x"03f00793",
    00000238 => x"fa8c0513",
    00000239 => x"00f40463",
    00000240 => x"fbc48513",
    00000241 => x"141000ef",
    00000242 => x"f75ff06f",
    00000243 => x"ffff1537",
    00000244 => x"db850513",
    00000245 => x"1310006f",
    00000246 => x"800007b7",
    00000247 => x"0007a783",
    00000248 => x"00079863",
    00000249 => x"ffff1537",
    00000250 => x"e1c50513",
    00000251 => x"1190006f",
    00000252 => x"ff010113",
    00000253 => x"00112623",
    00000254 => x"30047073",
    00000255 => x"00000013",
    00000256 => x"00000013",
    00000257 => x"ffff1537",
    00000258 => x"e3850513",
    00000259 => x"0f9000ef",
    00000260 => x"075000ef",
    00000261 => x"fe051ee3",
    00000262 => x"ff002783",
    00000263 => x"00078067",
    00000264 => x"0000006f",
    00000265 => x"ff010113",
    00000266 => x"00812423",
    00000267 => x"00050413",
    00000268 => x"ffff1537",
    00000269 => x"e4850513",
    00000270 => x"00112623",
    00000271 => x"0c9000ef",
    00000272 => x"03040513",
    00000273 => x"0ff57513",
    00000274 => x"02d000ef",
    00000275 => x"30047073",
    00000276 => x"00000013",
    00000277 => x"00000013",
    00000278 => x"00100513",
    00000279 => x"155000ef",
    00000280 => x"0000006f",
    00000281 => x"fe010113",
    00000282 => x"01212823",
    00000283 => x"00050913",
    00000284 => x"ffff1537",
    00000285 => x"00912a23",
    00000286 => x"e5450513",
    00000287 => x"ffff14b7",
    00000288 => x"00812c23",
    00000289 => x"01312623",
    00000290 => x"00112e23",
    00000291 => x"01c00413",
    00000292 => x"075000ef",
    00000293 => x"fc848493",
    00000294 => x"ffc00993",
    00000295 => x"008957b3",
    00000296 => x"00f7f793",
    00000297 => x"00f487b3",
    00000298 => x"0007c503",
    00000299 => x"ffc40413",
    00000300 => x"7c4000ef",
    00000301 => x"ff3414e3",
    00000302 => x"01c12083",
    00000303 => x"01812403",
    00000304 => x"01412483",
    00000305 => x"01012903",
    00000306 => x"00c12983",
    00000307 => x"02010113",
    00000308 => x"00008067",
    00000309 => x"fb010113",
    00000310 => x"04112623",
    00000311 => x"04512423",
    00000312 => x"04612223",
    00000313 => x"04712023",
    00000314 => x"02812e23",
    00000315 => x"02a12c23",
    00000316 => x"02b12a23",
    00000317 => x"02c12823",
    00000318 => x"02d12623",
    00000319 => x"02e12423",
    00000320 => x"02f12223",
    00000321 => x"03012023",
    00000322 => x"01112e23",
    00000323 => x"01c12c23",
    00000324 => x"01d12a23",
    00000325 => x"01e12823",
    00000326 => x"01f12623",
    00000327 => x"34202473",
    00000328 => x"800007b7",
    00000329 => x"00778793",
    00000330 => x"06f41a63",
    00000331 => x"00000513",
    00000332 => x"065000ef",
    00000333 => x"64c000ef",
    00000334 => x"fe002783",
    00000335 => x"0027d793",
    00000336 => x"00a78533",
    00000337 => x"00f537b3",
    00000338 => x"00b785b3",
    00000339 => x"660000ef",
    00000340 => x"03c12403",
    00000341 => x"04c12083",
    00000342 => x"04812283",
    00000343 => x"04412303",
    00000344 => x"04012383",
    00000345 => x"03812503",
    00000346 => x"03412583",
    00000347 => x"03012603",
    00000348 => x"02c12683",
    00000349 => x"02812703",
    00000350 => x"02412783",
    00000351 => x"02012803",
    00000352 => x"01c12883",
    00000353 => x"01812e03",
    00000354 => x"01412e83",
    00000355 => x"01012f03",
    00000356 => x"00c12f83",
    00000357 => x"05010113",
    00000358 => x"30200073",
    00000359 => x"00700793",
    00000360 => x"00f41863",
    00000361 => x"8041a783",
    00000362 => x"00100513",
    00000363 => x"02079863",
    00000364 => x"ffff1537",
    00000365 => x"e5850513",
    00000366 => x"74c000ef",
    00000367 => x"00040513",
    00000368 => x"ea5ff0ef",
    00000369 => x"ffff1537",
    00000370 => x"e6c50513",
    00000371 => x"738000ef",
    00000372 => x"34102573",
    00000373 => x"e91ff0ef",
    00000374 => x"00500513",
    00000375 => x"e49ff0ef",
    00000376 => x"ff010113",
    00000377 => x"00000513",
    00000378 => x"00112623",
    00000379 => x"00812423",
    00000380 => x"74c000ef",
    00000381 => x"09e00513",
    00000382 => x"788000ef",
    00000383 => x"00000513",
    00000384 => x"780000ef",
    00000385 => x"00050413",
    00000386 => x"00000513",
    00000387 => x"750000ef",
    00000388 => x"00c12083",
    00000389 => x"0ff47513",
    00000390 => x"00812403",
    00000391 => x"01010113",
    00000392 => x"00008067",
    00000393 => x"ff010113",
    00000394 => x"00112623",
    00000395 => x"00812423",
    00000396 => x"00000513",
    00000397 => x"708000ef",
    00000398 => x"00500513",
    00000399 => x"744000ef",
    00000400 => x"00000513",
    00000401 => x"73c000ef",
    00000402 => x"00050413",
    00000403 => x"00147413",
    00000404 => x"00000513",
    00000405 => x"708000ef",
    00000406 => x"fc041ce3",
    00000407 => x"00c12083",
    00000408 => x"00812403",
    00000409 => x"01010113",
    00000410 => x"00008067",
    00000411 => x"ff010113",
    00000412 => x"00000513",
    00000413 => x"00112623",
    00000414 => x"6c4000ef",
    00000415 => x"00600513",
    00000416 => x"700000ef",
    00000417 => x"00c12083",
    00000418 => x"00000513",
    00000419 => x"01010113",
    00000420 => x"6cc0006f",
    00000421 => x"ff010113",
    00000422 => x"00812423",
    00000423 => x"00050413",
    00000424 => x"01055513",
    00000425 => x"0ff57513",
    00000426 => x"00112623",
    00000427 => x"6d4000ef",
    00000428 => x"00845513",
    00000429 => x"0ff57513",
    00000430 => x"6c8000ef",
    00000431 => x"0ff47513",
    00000432 => x"00812403",
    00000433 => x"00c12083",
    00000434 => x"01010113",
    00000435 => x"6b40006f",
    00000436 => x"ff010113",
    00000437 => x"00812423",
    00000438 => x"00050413",
    00000439 => x"00000513",
    00000440 => x"00112623",
    00000441 => x"658000ef",
    00000442 => x"00300513",
    00000443 => x"694000ef",
    00000444 => x"00040513",
    00000445 => x"fa1ff0ef",
    00000446 => x"00000513",
    00000447 => x"684000ef",
    00000448 => x"00050413",
    00000449 => x"00000513",
    00000450 => x"654000ef",
    00000451 => x"00c12083",
    00000452 => x"0ff47513",
    00000453 => x"00812403",
    00000454 => x"01010113",
    00000455 => x"00008067",
    00000456 => x"fd010113",
    00000457 => x"02812423",
    00000458 => x"02912223",
    00000459 => x"03212023",
    00000460 => x"01312e23",
    00000461 => x"01412c23",
    00000462 => x"02112623",
    00000463 => x"00050913",
    00000464 => x"00058993",
    00000465 => x"00c10493",
    00000466 => x"00000413",
    00000467 => x"00400a13",
    00000468 => x"02091e63",
    00000469 => x"544000ef",
    00000470 => x"00a481a3",
    00000471 => x"00140413",
    00000472 => x"fff48493",
    00000473 => x"ff4416e3",
    00000474 => x"02c12083",
    00000475 => x"02812403",
    00000476 => x"00c12503",
    00000477 => x"02412483",
    00000478 => x"02012903",
    00000479 => x"01c12983",
    00000480 => x"01812a03",
    00000481 => x"03010113",
    00000482 => x"00008067",
    00000483 => x"00898533",
    00000484 => x"f41ff0ef",
    00000485 => x"fc5ff06f",
    00000486 => x"fd010113",
    00000487 => x"01412c23",
    00000488 => x"80418793",
    00000489 => x"02812423",
    00000490 => x"02112623",
    00000491 => x"02912223",
    00000492 => x"03212023",
    00000493 => x"01312e23",
    00000494 => x"01512a23",
    00000495 => x"01612823",
    00000496 => x"01712623",
    00000497 => x"01812423",
    00000498 => x"00100713",
    00000499 => x"00e7a023",
    00000500 => x"fe802783",
    00000501 => x"00050413",
    00000502 => x"80418a13",
    00000503 => x"0087f793",
    00000504 => x"00078a63",
    00000505 => x"fe802783",
    00000506 => x"00400513",
    00000507 => x"0047f793",
    00000508 => x"04079663",
    00000509 => x"02041863",
    00000510 => x"ffff1537",
    00000511 => x"e7450513",
    00000512 => x"504000ef",
    00000513 => x"008005b7",
    00000514 => x"00040513",
    00000515 => x"f15ff0ef",
    00000516 => x"4788d7b7",
    00000517 => x"afe78793",
    00000518 => x"02f50463",
    00000519 => x"00000513",
    00000520 => x"01c0006f",
    00000521 => x"ffff1537",
    00000522 => x"e9450513",
    00000523 => x"4d8000ef",
    00000524 => x"db1ff0ef",
    00000525 => x"fc0518e3",
    00000526 => x"00300513",
    00000527 => x"be9ff0ef",
    00000528 => x"008009b7",
    00000529 => x"00498593",
    00000530 => x"00040513",
    00000531 => x"ed5ff0ef",
    00000532 => x"00050a93",
    00000533 => x"00898593",
    00000534 => x"00040513",
    00000535 => x"ec5ff0ef",
    00000536 => x"ff002c03",
    00000537 => x"00050b13",
    00000538 => x"ffcafb93",
    00000539 => x"00000913",
    00000540 => x"00000493",
    00000541 => x"00c98993",
    00000542 => x"013905b3",
    00000543 => x"052b9c63",
    00000544 => x"016484b3",
    00000545 => x"00200513",
    00000546 => x"fa049ae3",
    00000547 => x"ffff1537",
    00000548 => x"ea050513",
    00000549 => x"470000ef",
    00000550 => x"02c12083",
    00000551 => x"02812403",
    00000552 => x"800007b7",
    00000553 => x"0157a023",
    00000554 => x"000a2023",
    00000555 => x"02412483",
    00000556 => x"02012903",
    00000557 => x"01c12983",
    00000558 => x"01812a03",
    00000559 => x"01412a83",
    00000560 => x"01012b03",
    00000561 => x"00c12b83",
    00000562 => x"00812c03",
    00000563 => x"03010113",
    00000564 => x"00008067",
    00000565 => x"00040513",
    00000566 => x"e49ff0ef",
    00000567 => x"012c07b3",
    00000568 => x"00a484b3",
    00000569 => x"00a7a023",
    00000570 => x"00490913",
    00000571 => x"f8dff06f",
    00000572 => x"ff010113",
    00000573 => x"00112623",
    00000574 => x"ea1ff0ef",
    00000575 => x"ffff1537",
    00000576 => x"ea450513",
    00000577 => x"400000ef",
    00000578 => x"ad1ff0ef",
    00000579 => x"0000006f",
    00000580 => x"ff010113",
    00000581 => x"00112623",
    00000582 => x"00812423",
    00000583 => x"00912223",
    00000584 => x"00058413",
    00000585 => x"00050493",
    00000586 => x"d45ff0ef",
    00000587 => x"00000513",
    00000588 => x"40c000ef",
    00000589 => x"00200513",
    00000590 => x"448000ef",
    00000591 => x"00048513",
    00000592 => x"d55ff0ef",
    00000593 => x"00040513",
    00000594 => x"438000ef",
    00000595 => x"00000513",
    00000596 => x"40c000ef",
    00000597 => x"00812403",
    00000598 => x"00c12083",
    00000599 => x"00412483",
    00000600 => x"01010113",
    00000601 => x"cc1ff06f",
    00000602 => x"fe010113",
    00000603 => x"00812c23",
    00000604 => x"00912a23",
    00000605 => x"01212823",
    00000606 => x"00112e23",
    00000607 => x"00b12623",
    00000608 => x"00300413",
    00000609 => x"00350493",
    00000610 => x"fff00913",
    00000611 => x"00c10793",
    00000612 => x"008787b3",
    00000613 => x"0007c583",
    00000614 => x"40848533",
    00000615 => x"fff40413",
    00000616 => x"f71ff0ef",
    00000617 => x"ff2414e3",
    00000618 => x"01c12083",
    00000619 => x"01812403",
    00000620 => x"01412483",
    00000621 => x"01012903",
    00000622 => x"02010113",
    00000623 => x"00008067",
    00000624 => x"ff010113",
    00000625 => x"00112623",
    00000626 => x"00812423",
    00000627 => x"00050413",
    00000628 => x"c9dff0ef",
    00000629 => x"00000513",
    00000630 => x"364000ef",
    00000631 => x"0d800513",
    00000632 => x"3a0000ef",
    00000633 => x"00040513",
    00000634 => x"cadff0ef",
    00000635 => x"00000513",
    00000636 => x"36c000ef",
    00000637 => x"00812403",
    00000638 => x"00c12083",
    00000639 => x"01010113",
    00000640 => x"c25ff06f",
    00000641 => x"fe010113",
    00000642 => x"800007b7",
    00000643 => x"00812c23",
    00000644 => x"0007a403",
    00000645 => x"00112e23",
    00000646 => x"00912a23",
    00000647 => x"01212823",
    00000648 => x"01312623",
    00000649 => x"01412423",
    00000650 => x"01512223",
    00000651 => x"02041863",
    00000652 => x"ffff1537",
    00000653 => x"e1c50513",
    00000654 => x"01812403",
    00000655 => x"01c12083",
    00000656 => x"01412483",
    00000657 => x"01012903",
    00000658 => x"00c12983",
    00000659 => x"00812a03",
    00000660 => x"00412a83",
    00000661 => x"02010113",
    00000662 => x"2ac0006f",
    00000663 => x"ffff1537",
    00000664 => x"ea850513",
    00000665 => x"2a0000ef",
    00000666 => x"00040513",
    00000667 => x"9f9ff0ef",
    00000668 => x"ffff1537",
    00000669 => x"eb450513",
    00000670 => x"28c000ef",
    00000671 => x"00800537",
    00000672 => x"9e5ff0ef",
    00000673 => x"ffff1537",
    00000674 => x"ed050513",
    00000675 => x"278000ef",
    00000676 => x"208000ef",
    00000677 => x"00050493",
    00000678 => x"1dc000ef",
    00000679 => x"07900793",
    00000680 => x"0af49e63",
    00000681 => x"b3dff0ef",
    00000682 => x"00051663",
    00000683 => x"00300513",
    00000684 => x"975ff0ef",
    00000685 => x"ffff1537",
    00000686 => x"edc50513",
    00000687 => x"01045493",
    00000688 => x"244000ef",
    00000689 => x"00148493",
    00000690 => x"00800937",
    00000691 => x"fff00993",
    00000692 => x"00010a37",
    00000693 => x"fff48493",
    00000694 => x"07349063",
    00000695 => x"4788d5b7",
    00000696 => x"afe58593",
    00000697 => x"00800537",
    00000698 => x"e81ff0ef",
    00000699 => x"00800537",
    00000700 => x"00040593",
    00000701 => x"00450513",
    00000702 => x"e71ff0ef",
    00000703 => x"ff002a03",
    00000704 => x"008009b7",
    00000705 => x"ffc47413",
    00000706 => x"00000493",
    00000707 => x"00000913",
    00000708 => x"00c98a93",
    00000709 => x"01548533",
    00000710 => x"009a07b3",
    00000711 => x"02849663",
    00000712 => x"00898513",
    00000713 => x"412005b3",
    00000714 => x"e41ff0ef",
    00000715 => x"ffff1537",
    00000716 => x"ea050513",
    00000717 => x"f05ff06f",
    00000718 => x"00090513",
    00000719 => x"e85ff0ef",
    00000720 => x"01490933",
    00000721 => x"f91ff06f",
    00000722 => x"0007a583",
    00000723 => x"00448493",
    00000724 => x"00b90933",
    00000725 => x"e15ff0ef",
    00000726 => x"fbdff06f",
    00000727 => x"01c12083",
    00000728 => x"01812403",
    00000729 => x"01412483",
    00000730 => x"01012903",
    00000731 => x"00c12983",
    00000732 => x"00812a03",
    00000733 => x"00412a83",
    00000734 => x"02010113",
    00000735 => x"00008067",
    00000736 => x"ff010113",
    00000737 => x"f9402783",
    00000738 => x"f9002703",
    00000739 => x"f9402683",
    00000740 => x"fed79ae3",
    00000741 => x"00e12023",
    00000742 => x"00f12223",
    00000743 => x"00012503",
    00000744 => x"00412583",
    00000745 => x"01010113",
    00000746 => x"00008067",
    00000747 => x"f9800693",
    00000748 => x"fff00613",
    00000749 => x"00c6a023",
    00000750 => x"00a6a023",
    00000751 => x"00b6a223",
    00000752 => x"00008067",
    00000753 => x"fa402503",
    00000754 => x"0ff57513",
    00000755 => x"00008067",
    00000756 => x"fa002023",
    00000757 => x"fe002703",
    00000758 => x"00151513",
    00000759 => x"00000793",
    00000760 => x"04a77463",
    00000761 => x"000016b7",
    00000762 => x"00000713",
    00000763 => x"ffe68693",
    00000764 => x"04f6e663",
    00000765 => x"00367613",
    00000766 => x"0035f593",
    00000767 => x"fff78793",
    00000768 => x"01461613",
    00000769 => x"00c7e7b3",
    00000770 => x"01659593",
    00000771 => x"01871713",
    00000772 => x"00b7e7b3",
    00000773 => x"00e7e7b3",
    00000774 => x"10000737",
    00000775 => x"00e7e7b3",
    00000776 => x"faf02023",
    00000777 => x"00008067",
    00000778 => x"00178793",
    00000779 => x"01079793",
    00000780 => x"40a70733",
    00000781 => x"0107d793",
    00000782 => x"fa9ff06f",
    00000783 => x"ffe70513",
    00000784 => x"0fd57513",
    00000785 => x"00051a63",
    00000786 => x"0037d793",
    00000787 => x"00170713",
    00000788 => x"0ff77713",
    00000789 => x"f9dff06f",
    00000790 => x"0017d793",
    00000791 => x"ff1ff06f",
    00000792 => x"f71ff06f",
    00000793 => x"fa002783",
    00000794 => x"fe07cee3",
    00000795 => x"faa02223",
    00000796 => x"00008067",
    00000797 => x"ff1ff06f",
    00000798 => x"fa002503",
    00000799 => x"01f55513",
    00000800 => x"00008067",
    00000801 => x"ff5ff06f",
    00000802 => x"fa402503",
    00000803 => x"fe055ee3",
    00000804 => x"0ff57513",
    00000805 => x"00008067",
    00000806 => x"ff1ff06f",
    00000807 => x"fa402503",
    00000808 => x"01f55513",
    00000809 => x"00008067",
    00000810 => x"ff5ff06f",
    00000811 => x"ff010113",
    00000812 => x"00812423",
    00000813 => x"01212023",
    00000814 => x"00112623",
    00000815 => x"00912223",
    00000816 => x"00050413",
    00000817 => x"00a00913",
    00000818 => x"00044483",
    00000819 => x"00140413",
    00000820 => x"00049e63",
    00000821 => x"00c12083",
    00000822 => x"00812403",
    00000823 => x"00412483",
    00000824 => x"00012903",
    00000825 => x"01010113",
    00000826 => x"00008067",
    00000827 => x"01249663",
    00000828 => x"00d00513",
    00000829 => x"f71ff0ef",
    00000830 => x"00048513",
    00000831 => x"f69ff0ef",
    00000832 => x"fc9ff06f",
    00000833 => x"fa9ff06f",
    00000834 => x"00757513",
    00000835 => x"00367613",
    00000836 => x"0015f593",
    00000837 => x"00a51513",
    00000838 => x"00d61613",
    00000839 => x"00c56533",
    00000840 => x"00959593",
    00000841 => x"fa800793",
    00000842 => x"00b56533",
    00000843 => x"0007a023",
    00000844 => x"10056513",
    00000845 => x"00a7a023",
    00000846 => x"00008067",
    00000847 => x"fa800713",
    00000848 => x"00072683",
    00000849 => x"00757793",
    00000850 => x"00100513",
    00000851 => x"00f51533",
    00000852 => x"00d56533",
    00000853 => x"00a72023",
    00000854 => x"00008067",
    00000855 => x"fa800713",
    00000856 => x"00072683",
    00000857 => x"00757513",
    00000858 => x"00100793",
    00000859 => x"00a797b3",
    00000860 => x"fff7c793",
    00000861 => x"00d7f7b3",
    00000862 => x"00f72023",
    00000863 => x"00008067",
    00000864 => x"faa02623",
    00000865 => x"fa802783",
    00000866 => x"fe07cee3",
    00000867 => x"fac02503",
    00000868 => x"00008067",
    00000869 => x"f8400713",
    00000870 => x"00072683",
    00000871 => x"00100793",
    00000872 => x"00a797b3",
    00000873 => x"00d7c7b3",
    00000874 => x"00f72023",
    00000875 => x"00008067",
    00000876 => x"f8a02223",
    00000877 => x"00008067",
    00000878 => x"69617641",
    00000879 => x"6c62616c",
    00000880 => x"4d432065",
    00000881 => x"0a3a7344",
    00000882 => x"203a6820",
    00000883 => x"706c6548",
    00000884 => x"3a72200a",
    00000885 => x"73655220",
    00000886 => x"74726174",
    00000887 => x"3a75200a",
    00000888 => x"6c705520",
    00000889 => x"0a64616f",
    00000890 => x"203a7320",
    00000891 => x"726f7453",
    00000892 => x"6f742065",
    00000893 => x"616c6620",
    00000894 => x"200a6873",
    00000895 => x"4c203a6c",
    00000896 => x"2064616f",
    00000897 => x"6d6f7266",
    00000898 => x"616c6620",
    00000899 => x"200a6873",
    00000900 => x"45203a65",
    00000901 => x"75636578",
    00000902 => x"00006574",
    00000903 => x"65206f4e",
    00000904 => x"75636578",
    00000905 => x"6c626174",
    00000906 => x"76612065",
    00000907 => x"616c6961",
    00000908 => x"2e656c62",
    00000909 => x"00000000",
    00000910 => x"746f6f42",
    00000911 => x"2e676e69",
    00000912 => x"0a0a2e2e",
    00000913 => x"00000000",
    00000914 => x"52450a07",
    00000915 => x"5f524f52",
    00000916 => x"00000000",
    00000917 => x"00007830",
    00000918 => x"58450a0a",
    00000919 => x"54504543",
    00000920 => x"204e4f49",
    00000921 => x"7561636d",
    00000922 => x"003d6573",
    00000923 => x"70204020",
    00000924 => x"00003d63",
    00000925 => x"69617741",
    00000926 => x"676e6974",
    00000927 => x"6f656e20",
    00000928 => x"32337672",
    00000929 => x"6578655f",
    00000930 => x"6e69622e",
    00000931 => x"202e2e2e",
    00000932 => x"00000000",
    00000933 => x"64616f4c",
    00000934 => x"2e676e69",
    00000935 => x"00202e2e",
    00000936 => x"00004b4f",
    00000937 => x"0000000a",
    00000938 => x"74697257",
    00000939 => x"78302065",
    00000940 => x"00000000",
    00000941 => x"74796220",
    00000942 => x"74207365",
    00000943 => x"5053206f",
    00000944 => x"6c662049",
    00000945 => x"20687361",
    00000946 => x"78302040",
    00000947 => x"00000000",
    00000948 => x"7928203f",
    00000949 => x"20296e2f",
    00000950 => x"00000000",
    00000951 => x"616c460a",
    00000952 => x"6e696873",
    00000953 => x"2e2e2e67",
    00000954 => x"00000020",
    00000955 => x"0a0a0a0a",
    00000956 => x"4e203c3c",
    00000957 => x"56524f45",
    00000958 => x"42203233",
    00000959 => x"6c746f6f",
    00000960 => x"6564616f",
    00000961 => x"3e3e2072",
    00000962 => x"4c420a0a",
    00000963 => x"203a5644",
    00000964 => x"20727041",
    00000965 => x"32203231",
    00000966 => x"0a313230",
    00000967 => x"3a565748",
    00000968 => x"00002020",
    00000969 => x"4b4c430a",
    00000970 => x"0020203a",
    00000971 => x"4553550a",
    00000972 => x"00203a52",
    00000973 => x"53494d0a",
    00000974 => x"00203a41",
    00000975 => x"58455a0a",
    00000976 => x"00203a54",
    00000977 => x"4f52500a",
    00000978 => x"00203a43",
    00000979 => x"454d490a",
    00000980 => x"00203a4d",
    00000981 => x"74796220",
    00000982 => x"40207365",
    00000983 => x"00000020",
    00000984 => x"454d440a",
    00000985 => x"00203a4d",
    00000986 => x"75410a0a",
    00000987 => x"6f626f74",
    00000988 => x"6920746f",
    00000989 => x"3828206e",
    00000990 => x"202e7329",
    00000991 => x"73657250",
    00000992 => x"656b2073",
    00000993 => x"6f742079",
    00000994 => x"6f626120",
    00000995 => x"0a2e7472",
    00000996 => x"00000000",
    00000997 => x"726f6241",
    00000998 => x"2e646574",
    00000999 => x"00000a0a",
    00001000 => x"444d430a",
    00001001 => x"00203e3a",
    00001002 => x"53207962",
    00001003 => x"68706574",
    00001004 => x"4e206e61",
    00001005 => x"69746c6f",
    00001006 => x"0000676e",
    00001007 => x"61766e49",
    00001008 => x"2064696c",
    00001009 => x"00444d43",
    00001010 => x"33323130",
    00001011 => x"37363534",
    00001012 => x"42413938",
    00001013 => x"46454443",
    others   => x"00000000"
  );

end neorv32_bootloader_image;

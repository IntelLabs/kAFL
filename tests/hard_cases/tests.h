/*
 * Copyright 2019 Sergej Schumilo, Cornelius Aschermann
 *
 * SPDX-License-Identifier: MIT
 */

uint64_t as_u64(char* input){
  return *((uint64_t*)(input));
}

uint64_t calc_hash(uint8_t* data, size_t len){
  uint64_t res = 0x0;
  size_t i = 0;
  for(i=0; i < len; i++){
    res += data[i];
  }
  return res;
}

char test_loop(char* input, size_t len){
  char* cmpval = "LOOPCHECK";
  if(len >= 32 ){
    int counter = 0;
	int i = 0;
    for(i = 0; i<strlen(cmpval); i++){
      if(input[i] == cmpval[i]){
        counter +=1;
      }
    }
    if(counter == strlen(cmpval)){
      test_panic("LOOP CHECK...\n"); /* boom! bug incoming... */
    }
  }
  return 0;
}

char test_hash(char* input, size_t len){
  if(len >= 32 ){
    if( as_u64(input) == calc_hash( (uint8_t*)input+8, len-8 ) ){
        if(input[8] == 'H'){
        if(input[9] == 'A'){
        if(input[10] == 'S'){
        if(input[11] == 'H'){
          test_panic("HASH CHECK...\n"); /* boom! bug incoming... */
        }}}}}}
  return 0;
}

char test_hash2(char* input, size_t len){
  if(len >= 32 ){
    if( as_u64(input) == calc_hash( (uint8_t*)input+8, len-8 ) ){
      if( as_u64(input+8) == calc_hash( (uint8_t*)input+16, len-16 ) ){
        if(input[16] == 'H'){
        if(input[17] == 'A'){
        if(input[18] == 'S'){
        if(input[19] == 'H'){
        if(input[20] == '2'){
          test_panic("HASH2 CHECK...\n"); /* boom! bug incoming... */
        }}}}}}}}
  return 0;
}

char test_se(char* input, size_t len){
  char* data = "0123456789abcdef";
  if(len >= 32 ){
    if(as_u64(input)==as_u64("MAGICHDR")){
      if(as_u64(input+8) * as_u64(input+8) == 857665508961587041ULL){ // "1337\0\0\0\0".unpack ** 2
        if(as_u64(input+16)<=32){
          return data[as_u64(input+16)];
        } else {
          test_panic("SE MULT INVERSION...\n"); /* boom! bug incoming... */
        }
      }
    }
  }
  return 0;
}

char test_feedback(char* input, size_t len){
	int *array = (int *)test_malloc(1332);
  //int *array = (int *)kmalloc(1332, GFP_KERNEL);
  if(len >= 32){
    if(input[0] == 'K')
      if(input[1] == 'E')
        if(input[2] == 'R')
          if(input[3] == 'N')
            if(input[4] == 'E')
              if(input[5] == 'L')
                if(input[6] == 'A')
                  if(input[7] == 'F')
                    if(input[8] == 'L')
                      test_panic("KAFL...\n"); /* boom! bug incoming... */
    if(input[0] == 'S')
      if(input[1] == 'E')
        if(input[2] == 'R')
          if(input[3] == 'G')
            if(input[4] == 'E')		
              if(input[5] == 'J')
                test_panic("SERGEJ...\n");

    if(input[0] == 'K'){
        if(input[1] == 'A'){
            if(input[2] == 'S'){
                if(input[3] == 'A'){
                    if(input[4] == 'N'){
              test_free(array);
              array[0] = 1234;
            }
          }
        }
      }
    }
  }
	test_free(array);
  return 0;
}

void test(char* input, size_t len){
  if(len >= 32){
    switch(input[0]){
      case('F'): test_feedback(input+1,len-1); break;
      case('S'): test_se(input+1,len-1); break;
      case('H'): test_hash(input+1,len-1); break;
      case('J'): test_hash2(input+1,len-1); break;
      case('L'): test_loop(input+1,len-1); break;
      case('X'): return;
    }
  }
}

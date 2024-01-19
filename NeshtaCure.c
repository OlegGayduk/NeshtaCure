#include <stdio.h>
#include <io.h>

int main(int argc, char const *argv[])
{
	unsigned short int i = 0;
    unsigned char crypt_bytes[0xA200 + 1];
    unsigned long int neshta_offset = 0, d = 0x93501B26, a = 0, b = 0, c = 0;

    //чтение из файла
    FILE *fp = fopen("002d0bbf9e77d8005d0a9dd10273139e06723baa", "rb+");
    if(!fp)
    {
        printf("Error occured while opening file\n");
        return 0;
    }
    
    //установка указателя в конец файла
    fseek(fp, 0, SEEK_END); 
    // получение физического размера файла и вычетание из него A200 байт, это и будет смещением до зашифрованного блока байт от начала файла 
    neshta_offset = ftell(fp) - 0xA200;  
    
    //перемещение указателя в файле на физическое смещение (offset) зашифрованного блока байт от конца файла
    fseek(fp, neshta_offset, SEEK_SET);

	//посимвольное считывание зашифрованных байт
    while((c=getc(fp))!= EOF)
    {
        crypt_bytes[i] = c;
        i = i + 1;
    }
    
    //цикл расшифровки neshta
	for(i = 0; i < 0x3E8; i++){
		c = (d * 0x8088405) + 1;
		d = c;
        a = c << 8;
        c = c >> 24;
        if(d > a) c = c - 1;
		crypt_bytes[i] = crypt_bytes[i] ^ c;
	}

	//установка указателя в начало файла 
	fseek(fp, 0, SEEK_SET);
    
    //запись расшифрованных байт в начало файла вместо тела вируса
    for(i = 0; i < 0xA200;i++) putc(crypt_bytes[i], fp);

    //обрезка файла до смещения зашифрованного блока
    if(chsize(fileno(fp), neshta_offset) != 0) {
    	printf("Error occured while changing size of cured file\n");
    }

    fclose(fp);

	return 0;
}
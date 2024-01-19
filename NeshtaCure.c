#include <stdio.h>
#include <io.h>

int main(int argc, char const *argv[])
{
	unsigned short int i = 0;
    unsigned char crypt_bytes[0xA200 + 1];
    unsigned long int neshta_offset = 0, d = 0x93501B26, a = 0, b = 0, c = 0;

    //������ �� �����
    FILE *fp = fopen("002d0bbf9e77d8005d0a9dd10273139e06723baa", "rb+");
    if(!fp)
    {
        printf("Error occured while opening file\n");
        return 0;
    }
    
    //��������� ��������� � ����� �����
    fseek(fp, 0, SEEK_END); 
    // ��������� ����������� ������� ����� � ��������� �� ���� A200 ����, ��� � ����� ��������� �� �������������� ����� ���� �� ������ ����� 
    neshta_offset = ftell(fp) - 0xA200;  
    
    //����������� ��������� � ����� �� ���������� �������� (offset) �������������� ����� ���� �� ����� �����
    fseek(fp, neshta_offset, SEEK_SET);

	//������������ ���������� ������������� ����
    while((c=getc(fp))!= EOF)
    {
        crypt_bytes[i] = c;
        i = i + 1;
    }
    
    //���� ����������� neshta
	for(i = 0; i < 0x3E8; i++){
		c = (d * 0x8088405) + 1;
		d = c;
        a = c << 8;
        c = c >> 24;
        if(d > a) c = c - 1;
		crypt_bytes[i] = crypt_bytes[i] ^ c;
	}

	//��������� ��������� � ������ ����� 
	fseek(fp, 0, SEEK_SET);
    
    //������ �������������� ���� � ������ ����� ������ ���� ������
    for(i = 0; i < 0xA200;i++) putc(crypt_bytes[i], fp);

    //������� ����� �� �������� �������������� �����
    if(chsize(fileno(fp), neshta_offset) != 0) {
    	printf("Error occured while changing size of cured file\n");
    }

    fclose(fp);

	return 0;
}
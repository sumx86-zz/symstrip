char * itoa( int num )
{
    short i;
    static char str[10];

    i = 9;
    str[i--] = '\x00';
    while ( num ) {
        str[i--] = (num % 10) + 48;
        num /= 10;
    }
    return &str[i+1];
}
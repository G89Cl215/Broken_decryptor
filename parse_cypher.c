#include <stddef.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include "Ma_Libft/includes/libft.h" //Needs a custom lib in the repo. lib can be found on my github. most be added to compilation (+ needs to be compiled as well)

#define LEN 	60
#define MAX 	0xffffffffffffffff
#define UNIT 	(unsigned long long)1

unsigned long long 	Cflag[LEN]; //representas all the possible values for each of the bytes of the flag. 4 long long ints encode the 256 value the byte can take, each bit representing a value. the values are sorted in big endian (i.e. zero is at the right most bit of the 4 lli)

void	init_flag(void)
{
	int	i = 0;

	while (i < LEN)
		Cflag[i++] = MAX; //each value is possible because none was eliminated
}

int	is_found(void)
{
	int	i = 0;

	while (i < LEN)
	{
		if (((Cflag[i] & (Cflag[i] - UNIT)) || (Cflag[i + 1]) || (Cflag[i + 2]) || (Cflag[i + 3]))
		&& ((Cflag[i + 1] & (Cflag[i + 1] - UNIT)) || (Cflag[i]) || (Cflag[i + 2]) || (Cflag[i + 3]))
		&& ((Cflag[i + 2] & (Cflag[i + 2] - UNIT)) || (Cflag[i]) || (Cflag[i + 1]) || (Cflag[i + 3]))
		&& ((Cflag[i + 3] & (Cflag[i + 3] - UNIT)) || (Cflag[i]) || (Cflag[i + 1]) || (Cflag[i + 2])))
			return 0; // the absurd condition only fails if two or more bits are 1 in the 4 long long int encoding the byte (i.e. 2 values of the byte are at least possible)
		i += 4;
	}
	return 1;
}

int decode_hex(char c)
{
	int res = 0;
	if (c >= '0' && c <='9')
		res = c - '0';
	else if (c >= 'a' && c <='f')
		res = c - 'a' +10;
	return res;
}

char	*get_next_output(int sckt)
{
	char	*output;

	send(sckt, "2\n", 2, 0); //you want to  encrypt the flag to decypher it (CTR_MODE has the same cyphering / decyphering mechanism: XOR of the same cypher stream
	send(sckt, "fbe22c3af35ff5f3077a0d9e3b9efb\n", 31, 0);	//flag you can find using parse_flag.c (each instance of the problem wil give you different values
	get_next_line(sckt, &output);
	while (output[1] == ')')
	{
		free(output);
		get_next_line(sckt, &output);
	}
	return output;
}

void	erase_hex(int j, char *s)
{
	unsigned long long	hex = MAX;
	unsigned long long	unit = UNIT;
	int			i;

	i = decode_hex(s[0]) << 4 | decode_hex(s[1]);
	if (i < 64)
	{
		hex ^= unit << i;
		Cflag[j + 3] &= hex;
	}
	else if (i < 128)
	{
		i -= 64;
		hex ^= unit << i;
		Cflag[j + 2] &= hex;
	}
	else if (i < 192)
	{
		i -= 128;
		hex ^= unit << i;
		Cflag[j + 1] &= hex;
	}
	else
	{
		i -= 192;
		hex ^= unit << i;
		Cflag[j] &= hex;
	}
//	printf("round byte: %c%c = %i code %lli\n", s[0], s[1], i, hex);
}

void	round_eliminate(int sckt)
{
	char	*otp = NULL;
	char	*otp_Cflag = NULL;
	int	i = 0;

	printf("|");
	otp = get_next_output(sckt);
	otp_Cflag = otp + 30; //cypher value starts at the 30th char
	printf("%s\n", otp_Cflag);
	while (i < LEN)
	{
		erase_hex(i, otp_Cflag + (i >> 1));
		i += 4;
	}
	free(otp);
}

void	output_Cflag()
{
	int	i = 0;
	int	j;

	printf("Flag: ");
	while (i < LEN)
	{
//		printf("%lli\n", Cflag[i]);
		if (Cflag[i])
		{
			j = 192;
			while (Cflag[i] > 1)
			{
				Cflag[i] >>= 1;
				j++;
			}
		}
		else if (Cflag[i + 1])
		{
			j = 128;
			while (Cflag[i + 1] > 1)
			{
				Cflag[i + 1] >>= 1;
				j++;
			}
		}
		else if (Cflag[i + 2])
		{
			j = 64;
			while (Cflag[i + 2] > 1)
			{
				Cflag[i + 2] >>= 1;
				j++;
			}
		}
		else
		{
			j = 0;
			while (Cflag[i + 3] > 1)
			{
				Cflag[i + 3] >>= 1;
				j++;
			}
		}
		printf("%x ",j);
		i += 4;
	}
	printf("\n");
}

int main()
{
	struct addrinfo 	*addr;
	int			sckt;

	printf("debug\n");
	getaddrinfo("167.71.143.20", "31003", NULL, &addr); // the params of the instance of the challenge given by htb
	sckt = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
	printf("connect state: %i, socket:%i\n", connect(sckt, addr->ai_addr, addr->ai_addrlen), sckt);
	init_flag();
	while (!is_found())
		round_eliminate(sckt);
	output_Cflag();
	close(sckt);
}

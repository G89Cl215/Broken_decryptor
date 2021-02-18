#include <stddef.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include "Ma_Libft/includes/libft.h"

#define LEN 	60
#define MAX 	0xfffffffffffffff
#define UNIT 	(unsigned long long)1

unsigned long long 	Cflag[LEN];

void	init_flag(void)
{
	int	i = 0;

	while (i < LEN)
		Cflag[i++] = MAX;
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
			return 0;
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

	send(sckt, "2\n", 2, 0);
	send(sckt, "19702cc4ec8398d1824d5ffa847a83\n", 31, 0); //flag I found using parse_flag.c
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

	while (i < LEN)
	{
//		printf("%lli\n", Cflag[i]);
		if (Cflag[i])
		{
			j = 191;
			while (Cflag[i] > 1)
			{
				Cflag[i] >>= 1;
				j++;
			}
		}
		else if (Cflag[i + 1])
		{
			j = 127;
			while (Cflag[i + 1] > 1)
			{
				Cflag[i + 1] >>= 1;
				j++;
			}
		}
		else if (Cflag[i + 2])
		{
			j = 63;
			while (Cflag[i + 2] > 1)
			{
				Cflag[i + 2] >>= 1;
				j++;
			}
		}
		else
		{
			j = -1;
			while (Cflag[i + 3] > 1)
			{
				Cflag[i + 3] >>= 1;
				j++;
			}
		}
		printf("j = %i %x\n", j, j);
		i += 4;
	}
}

int main()
{
	struct addrinfo 	*addr;
	int			sckt;

	printf("debug sizeof : %i\n", sizeof(Cflag[0]));
	getaddrinfo("167.71.143.20", "32575", NULL, &addr);
	sckt = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
	printf("connect state: %i, socket:%i\n", connect(sckt, addr->ai_addr, addr->ai_addrlen), sckt);
	init_flag();
	while (!is_found())
		round_eliminate(sckt);
	output_Cflag();
	close(sckt);
}

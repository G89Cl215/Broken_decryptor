#include <stddef.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include "Ma_Libft/includes/libft.h"
#define LEN 	30
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
		if (((Cflag[i] & (Cflag[i] - UNIT)) || (Cflag[i + 1]))
		&& ((Cflag[i + 1] & (Cflag[i + 1] - UNIT)) || (Cflag[i])))
			return 0;
		i += 2;
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

	send(sckt, "1\n", 2, 0);
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
	if (i < 128)
	{
		hex ^= unit << i;
		Cflag[j + 1] &= hex;
	}
	else
	{
		i -= 128;
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
	otp_Cflag = otp + 13; 
	printf("%s\n", otp_Cflag);
	while (i < LEN)
	{
		erase_hex(i, otp_Cflag + i);
		i += 2;
	}
	free(otp);
}

void	output_Cflag()
{
	int	i = 0;
	int	j;

	while (i < LEN)
	{
		printf("%lli\n", Cflag[i]);
		if (Cflag[i])
		{
			j = 125;
			while (Cflag[i] > 1)
			{
				Cflag[i] >>= 1;
				j++;
			}
		}
		else
		{
			j = -1;
			while (Cflag[i + 1] > 1)
			{
				Cflag[i + 1] >>= 1;
				j++;
			}
		}
		printf("j = %i %x ", j, j);
		i += 2;
	}
}

int main()
{
	struct addrinfo 	*addr;
	int			sckt;

	printf("debug\n");
	getaddrinfo("167.71.143.20", "32575", NULL, &addr);
	sckt = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
	printf("connect state: %i, socket:%i\n", connect(sckt, addr->ai_addr, addr->ai_addrlen), sckt);
	init_flag();
	while (!is_found())
		round_eliminate(sckt);
	output_Cflag();
	close(sckt);
}

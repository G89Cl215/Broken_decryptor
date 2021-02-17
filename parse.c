#include <stddef.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include "Ma_Libft/includes/libft.h"
#define LEN 	15

unsigned long long 	Cflag[LEN];

void	init_flag(void)
{
	int	i = 0;

	while (i < LEN)
		Cflag[i++] = 0xffffffff;
}



int	is_found(void)
{
	int	i = 0;

	while (i < LEN)
	{
		if (Cflag[i] & Cflag[i] - 1)
			return 0;
		i++;
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
	unsigned long long	hex = 0xffffffff;
	unsigned long long	unit = 1;
	int			i;

	i = decode_hex(s[0]) << 4 | decode_hex(s[1]);
	hex ^= unit << i;
	Cflag[j] &= hex;
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
		erase_hex(i, otp_Cflag + (i << 1));
		i++;
	}
	free(otp);
}

void	output_Cflag()
{
	int	i = 0;
	int	j;

	while (i < LEN)
	{
		j = -1;
		while (Cflag[i])
		{
			Cflag[i] >>= 1;
			j++;
		}
		printf("%x", j);
		i++;
	}
}

int main()
{
	struct addrinfo 	*addr;
	int			sckt;

	printf("debug\n");
	getaddrinfo("206.189.18.188", "31832", NULL, &addr);
	sckt = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
	printf("connect state: %i, socket:%i\n", connect(sckt, addr->ai_addr, addr->ai_addrlen), sckt);
	init_flag();
	while (!is_found())
		round_eliminate(sckt);
	output_Cflag();
	close(sckt);
}

NAME		:=	ft_ping
SRCS		:=	srcs/main.c \
				srcs/checksum.c\
				srcs/dns.c\
				srcs/print_message_treatment.c\
				srcs/inits.c

HDRS		:=	incs/ft_ping.h

OBJS		:=	$(addprefix objs/,$(notdir $(patsubst %.c,%.o,$(SRCS))))
OBJS_BONUS	:=	$(addprefix objs/,$(notdir $(patsubst %.c,%.o,$(SRCS_BONUS))))

CC			:=	gcc
CFLAGS		:=	-Iincs
LDFLAGS		:=  -lm
RM			:=	rm -f

all:			$(NAME)

$(NAME):		$(OBJS)
				@echo "Linking $(NAME)"
				@$(CC) $^ -o $@ $(LDFLAGS)

objs/%.o:		srcs/%.c $(HDRS)
				@mkdir -p objs
				@echo "Compiling $<"
				@$(CC) $(CFLAGS) -c $< -o $@

clean:
				@echo "Deleting object files"
				@$(RM) $(OBJS)

fclean:			clean
				@$(RM) $(NAME)

re: 			fclean all

.PHONY:			all clean fclean re
NAME		:=	ft_ping
SRCS		:=	srcs/main.c

HDRS		:=	

OBJS		:=	$(addprefix objs/,$(notdir $(patsubst %.c,%.o,$(SRCS))))
OBJS_BONUS	:=	$(addprefix objs/,$(notdir $(patsubst %.c,%.o,$(SRCS_BONUS))))

CC			:=	gcc
CFLAGS		:=	-Iincs -O3
LDFLAGS		:=	
RM			:=	rm -f

all:			$(NAME)

$(NAME):		$(OBJS)
				@echo "Linking $(NAME)"
				@$(CC) $(LDFLAGS) $^ -o $@

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
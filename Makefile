NAME		:=	ft_ping
SRCS		:=	srcs/main.c

HDRS		:=	

OBJS		:=	$(addprefix objs/,$(notdir $(patsubst %.c,%.o,$(SRCS))))
OBJS_BONUS	:=	$(addprefix objs/,$(notdir $(patsubst %.c,%.o,$(SRCS_BONUS))))

CC			:=	gcc
CFLAGS		:=	-Wall -Wextra -Werror -Iincludes -O3
LDFLAGS		:=	-lm
RM			:=	rm -f

all:			$(NAME)

$(NAME):		$(OBJS) | libs
				@echo "Linking $(NAME)"
				@$(CC) $(LDFLAGS) $^ $(LIBS) -o $@

objs/%.o:		srcs/*/%.c $(HDRS)
				@mkdir -p objs
				@echo "Compiling $<"
				@$(CC) $(CFLAGS) -c $< -o $@

clean:
				@echo "Deleting object files"
				@$(RM) $(OBJS) $(OBJS_BONUS)
				@echo	"Cleaning libs"
				@$(MAKE) -s -C libft/ clean
				@$(MAKE) -s -C $(MLX_DIR)/ clean

fclean:			clean
				@$(RM) $(NAME)
				@echo	"Force cleaning libs"
				@$(MAKE) -s -C libft/ fclean
				@$(MAKE) -s -C $(MLX_DIR)/ clean
				@$(RM) -f $(MLX_NAME)

re: 			fclean all

.PHONY:			all clean fclean re libs bonus

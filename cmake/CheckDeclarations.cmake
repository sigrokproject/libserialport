include(CheckSymbolExists)

check_symbol_exists("BOTHER" "linux/termios.h" HAVE_DECL_BOTHER)

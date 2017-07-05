CFLAGS += -I../../ -I./

all: $(BUILDDIR)DBManagerPlugin$(DLSUFFICS)

dbauth$(OBJSUFFICS): dbauth.c
	$(CC) $(DCFLAGS) $(CFLAGS) dbauth.c

db$(OBJSUFFICS): db.c
	$(CC) $(DCFLAGS) $(CFLAGS) db.c

cache$(OBJSUFFICS): cache.c dbauth.c
	$(CC) $(DCFLAGS) $(CFLAGS) cache.c dbauth.c

$(BUILDDIR)DBManagerPlugin$(DLSUFFICS): dbauth$(OBJSUFFICS) db$(OBJSUFFICS) cache$(OBJSUFFICS)
	$(LN) $(LNOUT)../../$(BUILDDIR)DBManagerPlugin$(DLSUFFICS) $(LDFLAGS) $(DLFLAGS) dbauth$(OBJSUFFICS) db$(OBJSUFFICS) cache$(OBJSUFFICS)

clean:
	@$(REMOVECOMMAND) *$(OBJSUFFICS)

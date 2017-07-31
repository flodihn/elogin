erl -config config/dev.config -pa ebin -pa deps/*/ebin +K true +P 1000000 -env ERL_MAX_PORTS 65535 -sname elogin -s elogin_app start $1

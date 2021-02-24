
run: force
	cpp x.zq | egrep -v '^#.*' > x.zq.cpp
	zq -f table -z x.zq.cpp bb.zng

run-z: force
	cpp homers.zq | egrep -v '^#.*' > homers.zq.cpp
	zq -f table -z homers.zq.cpp bb.zng

run-sql: force
	cpp homers.sql | egrep -v '^#.*' > homers.sql.cpp
	zq -f table -z homers.sql.cpp bb.zng


.PHONY: force

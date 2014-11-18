all: example_mararc example_csv1 example_csv1.txt \
     example_authoritative_mararc.txt example_recursive_mararc.txt \
     example_full_mararc example_csv2

clean:
	rm -f example_mararc example_csv1 example_csv1.txt \
	  example_authoritative_mararc.txt example_recursive_mararc.txt \
	  example_full_mararc

example_mararc: ../source/example_mararc
	cp ../source/example_mararc .

example_csv2: ../source/example_csv2
	cp ../source/example_csv2 example_csv2

example_csv1: ../source/example_simple_csv1
	cp ../source/example_simple_csv1 example_csv1

example_csv1.txt: ../source/example_simple_csv1
	cp ../source/example_simple_csv1 example_csv1.txt

example_authoritative_mararc.txt: ../source/example_auth_mararc
	cp ../source/example_auth_mararc example_authoritative_mararc.txt

example_recursive_mararc.txt: ../source/example_recursive_mararc
	cp ../source/example_recursive_mararc example_recursive_mararc.txt

example_full_mararc: ../source/example_full_mararc
	cp ../source/example_full_mararc example_full_mararc

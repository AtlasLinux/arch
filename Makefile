all:
	mkdir -p build
	gcc main.c -o build/arch

clean:
	rm -rf build
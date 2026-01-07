# EBPF Compilation
cd ebpf
make clean
make all
cd ..

# Python GUI
poetry install
poetry run python gui.py

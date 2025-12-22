from malduck import procmemelf, procmem


def test_hello():
    with procmemelf.from_file("tests/files/hello", image=True) as pelf:
        assert pelf.imgbase == 0x0
        assert pelf.readv(pelf.imgbase, 4) == b"\x7fELF"
        assert pelf.elf.elfclass == 64
        assert pelf.elf.get_machine_arch() == 'x64'
        assert pelf.elf.little_endian


def test_hello_static():
    with procmemelf.from_file("tests/files/hello_static", image=True) as pelf:
        assert pelf.imgbase == 0x400000
        assert pelf.readv(pelf.imgbase, 4) == b"\x7fELF"
        assert pelf.elf.elfclass == 64
        assert pelf.elf.get_machine_arch() == 'x64'
        assert pelf.elf.little_endian
        assert pelf.imgend == 7159808
        

def test_hello_32():
    with procmemelf.from_file("tests/files/hello_32", image=True) as pelf:
        assert pelf.imgbase == 0x0
        assert pelf.readv(pelf.imgbase, 4) == b"\x7fELF"
        assert pelf.elf.elfclass == 32
        assert pelf.elf.get_machine_arch() == 'x86'
        assert pelf.elf.little_endian
        assert pelf.imgend == 8192
        

def test_hello_32_static():
    with procmemelf.from_file("tests/files/hello_32_static", image=True) as pelf:
        assert pelf.imgbase == 0x8048000
        assert pelf.readv(pelf.imgbase, 4) == b"\x7fELF"
        assert pelf.elf.elfclass == 32
        assert pelf.elf.get_machine_arch() == 'x86'
        assert pelf.elf.little_endian
        assert pelf.imgend == 135200768


def test_hidden_32_static():
    with procmemelf.from_file("tests/files/hidden_32_static", image=True) as pelf:
        assert pelf.imgbase == 0x8048000
        assert pelf.readv(pelf.imgbase, 4) == b"\x7fELF"
        assert pelf.elf.elfclass == 32
        assert pelf.elf.get_machine_arch() == 'x86'
        assert pelf.elf.little_endian
        hidden_code = b"\x50\x53\x51\x52\xba\x0f\x00\x00\x00\xb9\x24\xd2\x0e\x08\xbb\x01\x00\x00\x00\xb8\x04\x00\x00"\
                      b"\x00\xcd\x80\x5a\x59\x5b\x58\x68\x73\x87\x04\x08\xc3\x28\x68\x69\x64\x64\x65\x6e\x20\x63\x6f"\
                      b"\x64\x65\x21\x29\x0a"
        assert pelf.readv(0x80ed200, len(hidden_code)) == hidden_code
        assert pelf.imgend == 135200768


def test_v2p_mapping_correctness():
    with procmemelf.from_file("tests/files/hello_32_static", image=True) as pelf:
        for segment in pelf.elf.iter_segments():
            if segment.header["p_type"] == "PT_LOAD" and segment.header["p_filesz"] > 0:
                p_vaddr = segment.header["p_vaddr"]
                p_offset = segment.header["p_offset"]
                p_filesz = segment.header["p_filesz"]
                
                # Test start of segment
                assert pelf.v2p(p_vaddr) == p_offset
                
                # Test middle of segment
                if p_filesz > 0x100:
                    assert pelf.v2p(p_vaddr + 0x100) == p_offset + 0x100
                
                # Test end of segment (last byte)
                assert pelf.v2p(p_vaddr + p_filesz - 1) == p_offset + p_filesz - 1


def test_no_negative_region_offsets():
    with procmemelf.from_file("tests/files/hello_32_static", image=True) as pelf:
        for region in pelf.regions:
            assert region.offset >= 0, f"Negative offset: {region.offset}"


def test_no_region_offset_overlap():
    with procmemelf.from_file("tests/files/hello_32_static", image=True) as pelf:
        sorted_regions = sorted(pelf.regions, key=lambda r: r.offset)
        for i in range(len(sorted_regions) - 1):
            current = sorted_regions[i]
            next_region = sorted_regions[i + 1]
            current_end = current.offset + current.size
            assert current_end <= next_region.offset, \
                f"Region overlap: [{hex(current.offset)}:{hex(current_end)}] and [{hex(next_region.offset)}:...]"


def test_imgbase_calculation():
    with procmemelf.from_file("tests/files/hello_32_static", image=True) as pelf:
        # Find the first PT_LOAD segment by file offset
        first_load_segment = None
        for segment in pelf.elf.iter_segments():
            if segment.header["p_type"] == "PT_LOAD" and segment.header["p_filesz"] > 0:
                if first_load_segment is None or segment.header["p_offset"] < first_load_segment.header["p_offset"]:
                    first_load_segment = segment
        
        expected_imgbase = first_load_segment.header["p_vaddr"] - first_load_segment.header["p_offset"]
        assert pelf.imgbase == expected_imgbase


def test_embedded_elf_in_memory_dump():
    # Load ELF file into a larger buffer with padding
    with open("tests/files/hello_32_static", "rb") as f:
        elf_data = f.read()
    
    padding = b"\x00" * 0x1000
    combined = padding + elf_data + padding
    
    # Create procmem with the combined buffer, ELF at offset 0x1000
    p = procmem(combined, base=0)
    
    # Find and load the embedded ELF
    for carved in procmemelf.load_binaries_from_memory(p):
        if carved.is_image:
            # Verify that v2p accounts for the embedding offset
            first_segment = None
            for seg in carved.elf.iter_segments():
                if seg.header["p_type"] == "PT_LOAD" and seg.header["p_filesz"] > 0:
                    first_segment = seg
                    break
            
            if first_segment:
                p_vaddr = first_segment.header["p_vaddr"]
                # The file offset should include the 0x1000 padding
                file_offset = carved.v2p(p_vaddr)
                assert file_offset == 0x1000 + first_segment.header["p_offset"], \
                    f"Expected {hex(0x1000 + first_segment.header['p_offset'])}, got {hex(file_offset)}"
            break

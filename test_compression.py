# tests/test_compression.py
import pytest
from compression import ProductionCompressionPrototype

def test_text_compression():
    proto = ProductionCompressionPrototype()
    data = "hello world" * 100
    result = proto.compress_text(data)
    assert len(result[0]) < len(data.encode())

def test_image_compression():
    proto = ProductionCompressionPrototype()
    img = np.random.randint(0, 256, (32, 32), dtype=np.uint8)
    result = proto.compress_image_hybrid_loop(img)
    assert result[2] < img.size

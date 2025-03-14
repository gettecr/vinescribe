import base64
import io
from PIL import Image, ImageOps


def resize_image(file_data: bytes, max_size=(300, 400), format: str = "jpeg") -> bytes:
    """Resize an image from an in-memory byte stream while maintaining aspect ratio.

    Args:
        file_data (bytes): The image file data (decoded from base64).
        max_size (tuple): Max width and height (default: 300x400).

    Returns:
        bytes: The resized image as an in-memory byte stream.
    """
    # Open image from bytes
    with ImageOps.exif_transpose(Image.open(io.BytesIO(file_data))) as img:
        img.thumbnail(max_size)  # Resize while maintaining aspect ratio

        # Save to an in-memory bytes buffer
        output_buffer = io.BytesIO()
        img.save(output_buffer, format=format)  # Keep original format
        return output_buffer.getvalue()  # Return resized image as bytes


def resize_image_base64(file_data: bytes, max_size=(300, 400)) -> str:
    """Resize an image and return it as a Base64-encoded string."""
    resized_bytes = resize_image(file_data, max_size=max_size)  # Call previous function
    return base64.urlsafe_b64encode(resized_bytes).decode("UTF-8")

import io

import dhash
from PIL import Image


class Favicon:
    @staticmethod
    def eval_dhash(favicon):
        try:
            icon = io.BytesIO(favicon)
            image = Image.open(icon)

            row, col = dhash.dhash_row_col(image)
            return dhash.format_hex(row, col)
        except Exception:  # pragma: no cover,pylint:disable=broad-except
            return None

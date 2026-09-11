"""
Generate simple ADCTIN icons programmatically
Requires: pip install Pillow
"""
from PIL import Image, ImageDraw, ImageFont
import os

def create_icon(size, output_path):
    # Create image with dark background
    img = Image.new('RGBA', (size, size), (26, 26, 46, 255))
    draw = ImageDraw.Draw(img)
    
    # Draw shield shape
    padding = size * 0.15
    shield_color = (193, 127, 89)  # Amber-gold
    
    # Simple shield: triangle pointing down + rectangle top
    points = [
        (size * 0.5, size * 0.15),           # Top center
        (size * 0.85, size * 0.3),           # Top right
        (size * 0.85, size * 0.55),          # Right
        (size * 0.5, size * 0.9),            # Bottom point
        (size * 0.15, size * 0.55),          # Left
        (size * 0.15, size * 0.3),           # Top left
    ]
    draw.polygon(points, fill=shield_color)
    
    # Draw a smaller inner shield (lighter)
    inner_points = [
        (size * 0.5, size * 0.3),
        (size * 0.72, size * 0.4),
        (size * 0.72, size * 0.55),
        (size * 0.5, size * 0.75),
        (size * 0.28, size * 0.55),
        (size * 0.28, size * 0.4),
    ]
    draw.polygon(inner_points, fill=(245, 240, 235))
    
    # Draw a dot in the center
    dot_r = size * 0.06
    cx, cy = size * 0.5, size * 0.5
    draw.ellipse([cx - dot_r, cy - dot_r, cx + dot_r, cy + dot_r], fill=(212, 92, 76))
    
    # Save
    img.save(output_path, 'PNG')
    print(f"✅ Created {output_path} ({size}x{size})")

# Create icons
icon_sizes = [16, 48, 128]
os.makedirs('icons', exist_ok=True)

for size in icon_sizes:
    create_icon(size, f'icons/icon-{size}.png')

print("\n✅ All icons created successfully!")
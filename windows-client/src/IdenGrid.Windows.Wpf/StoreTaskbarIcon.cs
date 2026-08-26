using System.Drawing;
using System.Drawing.Drawing2D;
using System.Drawing.Imaging;
using System.Drawing.Text;
using System.IO;
using System.Text;

namespace IdenGrid.Windows.Wpf;

internal static class StoreTaskbarIcon
{
    private static readonly string[] Palette =
        ["#315CFF", "#28C7B7", "#7C5CFC", "#F08A4B", "#E05278"];
    private static readonly int[] Sizes = [16, 24, 32, 48, 64, 128, 256];
    private const float BrandMarkScale = 0.28f;
    private const float SingleCharacterFontScale = 0.64f;
    private const float TwoCharacterFontScale = 0.46f;

    public static string LabelFor(string storeName, string storeId)
    {
        var normalized = storeName.Trim();
        var cjk = normalized.EnumerateRunes().FirstOrDefault(IsCjk);
        if (cjk.Value != 0) return cjk.ToString();

        var ascii = string.Concat(
            normalized.EnumerateRunes()
                .Where(rune => rune.IsAscii && char.IsLetterOrDigit((char)rune.Value))
                .Take(2)
                .Select(rune => rune.ToString()));
        if (!string.IsNullOrEmpty(ascii)) return ascii.ToUpperInvariant();

        var fallback = string.Concat(
            storeId.EnumerateRunes()
                .Where(rune => rune.IsAscii && char.IsLetterOrDigit((char)rune.Value))
                .TakeLast(2)
                .Select(rune => rune.ToString()));
        return string.IsNullOrEmpty(fallback) ? "?" : fallback.ToUpperInvariant();
    }

    public static string ColorFor(string storeId)
    {
        if (!ulong.TryParse(storeId, out var numericId))
        {
            numericId = 0;
            foreach (var rune in storeId.EnumerateRunes())
                numericId = unchecked((numericId * 16777619) ^ (uint)rune.Value);
        }
        return Palette[(int)(numericId % (ulong)Palette.Length)];
    }

    public static string Create(string storeRoot, string storeName, string storeId)
    {
        var source = Path.Combine(AppContext.BaseDirectory, "Assets", "idengrid.ico");
        if (!File.Exists(source)) throw new FileNotFoundException("缺少IdenGrid品牌图标", source);

        var identityRoot = Path.Combine(storeRoot, "Identity");
        Directory.CreateDirectory(identityRoot);
        var destination = Path.Combine(identityRoot, "store-taskbar.ico");
        var staging = destination + ".staging-" + Guid.NewGuid().ToString("N");
        var label = LabelFor(storeName, storeId);
        var badgeColor = ColorTranslator.FromHtml(ColorFor(storeId));

        try
        {
            using var sourceIcon = new Icon(source, 256, 256);
            using var logo = sourceIcon.ToBitmap();
            var frames = Sizes.Select(size => RenderFrame(logo, size, badgeColor, label)).ToArray();
            WriteIcon(staging, frames);
            File.Move(staging, destination, true);
            return destination;
        }
        finally
        {
            try { File.Delete(staging); } catch (IOException) { }
        }
    }

    private static bool IsCjk(Rune rune) =>
        rune.Value is >= 0x3400 and <= 0x4DBF or >= 0x4E00 and <= 0x9FFF;

    private static byte[] RenderFrame(Bitmap logo, int size, Color badgeColor, string label)
    {
        using var bitmap = new Bitmap(size, size, PixelFormat.Format32bppArgb);
        using var graphics = Graphics.FromImage(bitmap);
        graphics.Clear(Color.Transparent);
        graphics.CompositingMode = CompositingMode.SourceOver;
        graphics.CompositingQuality = CompositingQuality.HighQuality;
        graphics.InterpolationMode = InterpolationMode.HighQualityBicubic;
        graphics.PixelOffsetMode = PixelOffsetMode.HighQuality;
        graphics.SmoothingMode = SmoothingMode.AntiAlias;
        graphics.TextRenderingHint = TextRenderingHint.AntiAliasGridFit;
        var inset = Math.Max(1f, size * 0.035f);
        var background = new RectangleF(inset, inset, size - inset * 2, size - inset * 2);
        using var backgroundBrush = new SolidBrush(badgeColor);
        FillRoundedRectangle(graphics, backgroundBrush, background, size * 0.20f);

        using var font = new Font(
            "Microsoft YaHei UI",
            Math.Max(
                9f,
                size * (label.Length > 1 ? TwoCharacterFontScale : SingleCharacterFontScale)),
            FontStyle.Bold,
            GraphicsUnit.Pixel);
        using var textBrush = new SolidBrush(ReadableTextColor(badgeColor));
        using var format = new StringFormat
        {
            Alignment = StringAlignment.Center,
            LineAlignment = StringAlignment.Center,
            FormatFlags = StringFormatFlags.NoWrap,
        };
        graphics.DrawString(label, font, textBrush, background, format);

        var brandSize = Math.Max(6f, size * BrandMarkScale);
        var brandBacking = new RectangleF(inset, inset, brandSize + inset, brandSize + inset);
        using var brandBackingBrush = new SolidBrush(Color.White);
        graphics.FillEllipse(brandBackingBrush, brandBacking);
        var brand = new RectangleF(
            brandBacking.X + inset * 0.55f,
            brandBacking.Y + inset * 0.55f,
            brandSize,
            brandSize);
        graphics.DrawImage(logo, brand);

        using var stream = new MemoryStream();
        bitmap.Save(stream, ImageFormat.Png);
        return stream.ToArray();
    }

    private static Color ReadableTextColor(Color background)
    {
        var brightness = background.R * 0.299 + background.G * 0.587 + background.B * 0.114;
        return brightness >= 155 ? Color.FromArgb(255, 16, 32, 60) : Color.White;
    }

    private static void FillRoundedRectangle(
        Graphics graphics,
        Brush brush,
        RectangleF rectangle,
        float radius)
    {
        var diameter = Math.Min(radius * 2, Math.Min(rectangle.Width, rectangle.Height));
        using var path = new GraphicsPath();
        path.AddArc(rectangle.Left, rectangle.Top, diameter, diameter, 180, 90);
        path.AddArc(rectangle.Right - diameter, rectangle.Top, diameter, diameter, 270, 90);
        path.AddArc(
            rectangle.Right - diameter,
            rectangle.Bottom - diameter,
            diameter,
            diameter,
            0,
            90);
        path.AddArc(rectangle.Left, rectangle.Bottom - diameter, diameter, diameter, 90, 90);
        path.CloseFigure();
        graphics.FillPath(brush, path);
    }

    private static void WriteIcon(string path, IReadOnlyList<byte[]> frames)
    {
        using var file = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None);
        using var writer = new BinaryWriter(file, Encoding.UTF8, false);
        writer.Write((ushort)0);
        writer.Write((ushort)1);
        writer.Write((ushort)frames.Count);
        var offset = 6 + frames.Count * 16;
        for (var index = 0; index < frames.Count; index++)
        {
            var size = Sizes[index];
            writer.Write((byte)(size >= 256 ? 0 : size));
            writer.Write((byte)(size >= 256 ? 0 : size));
            writer.Write((byte)0);
            writer.Write((byte)0);
            writer.Write((ushort)1);
            writer.Write((ushort)32);
            writer.Write((uint)frames[index].Length);
            writer.Write((uint)offset);
            offset += frames[index].Length;
        }
        foreach (var frame in frames) writer.Write(frame);
    }
}

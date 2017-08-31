# OpenVAS Vulnerability Test 
# Description: Mageia Linux security check 
# $Id: mgasa-2016-0018.nasl 6562 2017-07-06 12:22:42Z cfischer $
 
# Authors: 
# Eero Volotinen <eero.volotinen@solinor.com> 
#
# Copyright:
# Copyright (c) 2015 Eero Volotinen, http://www.solinor.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#
if(description)
 {
script_oid("1.3.6.1.4.1.25623.1.0.131185");
script_version("$Revision: 6562 $");
script_tag(name:"creation_date", value:"2016-01-15 08:29:01 +0200 (Fri, 15 Jan 2016)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 14:22:42 +0200 (Thu, 06 Jul 2017) $");
script_name("Mageia Linux Local Check: mgasa-2016-0018");
script_tag(name: "insight", value: "The update_dimensions function in libavcodec/vp8.c in FFmpeg before 2.4.12, as used in Google Chrome before 46.0.2490.71 and other products, relies on a coefficient-partition count during multi-threaded operation, which allows remote attackers to cause a denial of service (race condition and memory corruption) or possibly have unspecified other impact via a crafted WebM file (CVE-2015-6761). The decode_ihdr_chunk function in libavcodec/pngdec.c in FFmpeg before 2.4.11 does not enforce uniqueness of the IHDR (aka image header) chunk in a PNG image, which allows remote attackers to cause a denial of service (out-of-bounds array access) or possibly have unspecified other impact via a crafted image with two or more of these chunks (CVE-2015-6818). The ff_sbr_apply function in libavcodec/aacsbr.c in FFmpeg before 2.4.11 does not check for a matching AAC frame syntax element before proceeding with Spectral Band Replication calculations, which allows remote attackers to cause a denial of service (out-of-bounds array access) or possibly have unspecified other impact via crafted AAC data (CVE-2015-6820). The ff_mpv_common_init function in libavcodec/mpegvideo.c in FFmpeg before 2.4.11 does not properly maintain the encoding context, which allows remote attackers to cause a denial of service (invalid pointer access) or possibly have unspecified other impact via crafted MPEG data (CVE-2015-6821). The destroy_buffers function in libavcodec/sanm.c in FFmpeg before 2.4.11 does not properly maintain height and width values in the video context, which allows remote attackers to cause a denial of service (segmentation violation and application crash) or possibly have unspecified other impact via crafted LucasArts Smush video data (CVE-2015-6822). The allocate_buffers function in libavcodec/alac.c in FFmpeg before 2.4.11 does not initialize certain context data, which allows remote attackers to cause a denial of service (segmentation violation) or possibly have unspecified other impact via crafted Apple Lossless Audio Codec (ALAC) data (CVE-2015-6823). The sws_init_context function in libswscale/utils.c in FFmpeg before 2.4.11 does not initialize certain pixbuf data structures, which allows remote attackers to cause a denial of service (segmentation violation) or possibly have unspecified other impact via crafted video data (CVE-2015-6824). The ff_frame_thread_init function in libavcodec/pthread_frame.c in FFmpeg before 2.4.11 mishandles certain memory-allocation failures, which allows remote attackers to cause a denial of service (invalid pointer access) or possibly have unspecified other impact via a crafted file, as demonstrated by an AVI file (CVE-2015-6825). The ff_rv34_decode_init_thread_copy function in libavcodec/rv34.c in FFmpeg before 2.4.11 does not initialize certain structure members, which allows remote attackers to cause a denial of service (invalid pointer access) or possibly have unspecified other impact via crafted RV30 or RV40 RealVideo data (CVE-2015-6826). The ljpeg_decode_yuv_scan function in libavcodec/mjpegdec.c in FFmpeg before 2.4.12 omits certain width and height checks, which allows remote attackers to cause a denial of service (out-of-bounds array access) or possibly have unspecified other impact via crafted MJPEG data (CVE-2015-8216). The init_tile function in libavcodec/jpeg2000dec.c in FFmpeg before 2.4.12 does not enforce minimum-value and maximum-value constraints on tile coordinates, which allows remote attackers to cause a denial of service (out-of-bounds array access) or possibly have unspecified other impact via crafted JPEG 2000 data (CVE-2015-8219). The jpeg2000_read_main_headers function in libavcodec/jpeg2000dec.c in FFmpeg before 2.4.12 does not enforce uniqueness of the SIZ marker in a JPEG 2000 image, which allows remote attackers to cause a denial of service (out-of-bounds heap-memory access) or possibly have unspecified other impact via a crafted image with two or more of these markers (CVE-2015-8363). Integer overflow in the ff_ivi_init_planes function in libavcodec/ivi.c in FFmpeg before 2.4.12 allows remote attackers to cause a denial of service (out-of-bounds heap-memory access) or possibly have unspecified other impact via crafted image dimensions in Indeo Video Interactive data (CVE-2015-8364). The smka_decode_frame function in libavcodec/smacker.c in FFmpeg before 2.4.12 does not verify that the data size is consistent with the number of channels, which allows remote attackers to cause a denial of service (out-of-bounds array access) or possibly have unspecified other impact via crafted Smacker data (CVE-2015-8365). The h264_slice_header_init function in libavcodec/h264_slice.c in FFmpeg before 2.4.12 does not validate the relationship between the number of threads and the number of slices, which allows remote attackers to cause a denial of service (out-of-bounds array access) or possibly have unspecified other impact via crafted H.264 data (CVE-2015-8661). The ff_dwt_decode function in libavcodec/jpeg2000dwt.c in FFmpeg before 2.4.12 does not validate the number of decomposition levels before proceeding with Discrete Wavelet Transform decoding, which allows remote attackers to cause a denial of service (out-of-bounds array access) or possibly have unspecified other impact via crafted JPEG 2000 data (CVE-2015-8662). The ff_get_buffer function in libavcodec/utils.c in FFmpeg before 2.4.12 preserves width and height values after a failure, which allows remote attackers to cause a denial of service (out-of-bounds array access) or possibly have unspecified other impact via a crafted .mov file (CVE-2015-8663)."); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_xref(name : "URL" , value : "https://advisories.mageia.org/MGASA-2016-0018.html");
script_cve_id("CVE-2015-6761","CVE-2015-6818","CVE-2015-6820","CVE-2015-6821","CVE-2015-6822","CVE-2015-6823","CVE-2015-6824","CVE-2015-6825","CVE-2015-6826","CVE-2015-8216","CVE-2015-8219","CVE-2015-8363","CVE-2015-8364","CVE-2015-8365","CVE-2015-8661","CVE-2015-8662","CVE-2015-8663");
script_tag(name:"cvss_base", value:"7.5");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_tag(name:"qod_type", value:"package");
script_dependencies("gather-package-list.nasl");
script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release");
script_category(ACT_GATHER_INFO);
script_tag(name : "summary", value : "Mageia Linux Local Security Checks mgasa-2016-0018");
script_copyright("Eero Volotinen");
script_family("Mageia Linux Local Security Checks");
exit(0);
}
include("revisions-lib.inc");
include("pkg-lib-rpm.inc");
release = get_kb_item("ssh/login/release");
res = "";
if(release == NULL)
{
 exit(0);
}
if(release == "MAGEIA5")
{
if ((res = isrpmvuln(pkg:"ffmpeg", rpm:"ffmpeg~2.4.12~1.mga5", rls:"MAGEIA5")) != NULL) {
  security_message(data:res);
  exit(0);
}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);
}

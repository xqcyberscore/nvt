###############################################################################
# OpenVAS Vulnerability Test
# $Id: deb_dla_1611.nasl 12870 2018-12-21 14:20:59Z cfischer $
#
# Auto-generated from advisory DLA 1611-1 and DLA 1611-2 using nvtgen 1.0
# Script version: 2.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (c) 2018 Greenbone Networks GmbH http://greenbone.net
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

# nb: This includes a manual merge of DLA 1611-1 and 1611-2

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.891611");
  script_version("$Revision: 12870 $");
  script_cve_id("CVE-2014-9317", "CVE-2015-6761", "CVE-2015-6818", "CVE-2015-6820", "CVE-2015-6821",
                "CVE-2015-6822", "CVE-2015-6823", "CVE-2015-6824", "CVE-2015-6825", "CVE-2015-6826",
                "CVE-2015-8216", "CVE-2015-8217", "CVE-2015-8363", "CVE-2015-8364", "CVE-2015-8661",
                "CVE-2015-8662", "CVE-2015-8663", "CVE-2016-10190", "CVE-2016-10191");
  script_name("Debian LTS Advisory ([SECURITY] [DLA 1611-1 and DLA 1611-2] libav security update)");
  script_tag(name:"last_modification", value:"$Date: 2018-12-21 15:20:59 +0100 (Fri, 21 Dec 2018) $");
  script_tag(name:"creation_date", value:"2018-12-21 00:00:00 +0100 (Fri, 21 Dec 2018)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2018/12/msg00009.html");
  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2018/12/msg00010.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (c) 2018 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8\.[0-9]+");
  script_tag(name:"affected", value:"libav on Debian Linux");
  script_tag(name:"solution", value:"For Debian 8 'Jessie', these problems have been fixed in version
6:11.12-1~deb8u3.

We recommend that you upgrade your libav packages.");
  script_tag(name:"summary",  value:"DLA 1611-1:

Several security issues have been corrected in multiple demuxers and
decoders of the libav multimedia library.

CVE-2014-9317

    The decode_ihdr_chunk function in libavcodec/pngdec.c allowed remote
    attackers to cause a denial of service (out-of-bounds heap access)
    and possibly had other unspecified impact via an IDAT before an IHDR
    in a PNG file. The issue got addressed by checking IHDR/IDAT order.

CVE-2015-6761

    The update_dimensions function in libavcodec/vp8.c in libav relies on
    a coefficient-partition count during multi-threaded operation, which
    allowed remote attackers to cause a denial of service (race condition
    and memory corruption) or possibly have unspecified other impact via
    a crafted WebM file. This issue has been resolved by using
    num_coeff_partitions in thread/buffer setup. The variable is not a
    constant and can lead to race conditions.

CVE-2015-6818

    The decode_ihdr_chunk function in libavcodec/pngdec.c did not enforce
    uniqueness of the IHDR (aka image header) chunk in a PNG image, which
    allowed remote attackers to cause a denial of service (out-of-bounds
    array access) or possibly have unspecified other impact via a crafted
    image with two or more of these chunks. This has now been fixed by
    only allowing one IHDR chunk. Multiple IHDR chunks are forbidden in
    PNG.

CVE-2015-6820

    The ff_sbr_apply function in libavcodec/aacsbr.c did not check for a
    matching AAC frame syntax element before proceeding with Spectral
    Band Replication calculations, which allowed remote attackers to
    cause a denial of service (out-of-bounds array access) or possibly
    have unspecified other impact via crafted AAC data. This has now been
    fixed by checking that the element type matches before applying SBR.

CVE-2015-6821

    The ff_mpv_common_init function in libavcodec/mpegvideo.c did not
    properly maintain the encoding context, which allowed remote
    attackers to cause a denial of service (invalid pointer access) or
    possibly have unspecified other impact via crafted MPEG data. The
    issue has been resolved by clearing pointers in ff_mpv_common_init().
    This ensures that no stale pointers leak through on any path.

CVE-2015-6822

    The destroy_buffers function in libavcodec/sanm.c did not properly
    maintain height and width values in the video context, which allowed
    remote attackers to cause a denial of service (segmentation violation
    and application crash) or possibly have unspecified other impact via
    crafted LucasArts Smush video data. The solution to this was to reset
    sizes in destroy_buffers() in avcodec/sanm.c.

CVE-2015-6823

    Other than stated in the debian/changelog file, this issue
    has not yet been fixed for libav in Debian jessie LTS.

CVE-2015-6824

    Other than stated in the debian/changelog file, this issue
    has not yet been fixed for libav in Debian jessie LTS.

CVE-2015-6825

    The ff_frame_thread_init function in libavcodec/pthread_frame.c
    mishandled certain memory-allocation failures, which allowed remote
    attackers to cause a denial of service (invalid pointer access) or
    possibly have unspecified other impact via a crafted file, as
    demonstrated by an AVI file. Clearing priv_data in
    avcodec/pthread_frame.c has resolved this and now avoids stale
    pointer in error case.

CVE-2015-6826

    The ff_rv34_decode_init_thread_copy function in libavcodec/rv34.c did
    not initialize certain structure members, which allowed remote
    attackers to cause a denial of service (invalid pointer access) or
    possibly have unspecified other impact via crafted (1) RV30 or (2)
    RV40 RealVideo data. This issue got addressed by clearing pointers in
    ff_rv34_decode_init_thread_copy() in avcodec/rv34.c, which avoids
    leaving stale pointers.

CVE-2015-8216

    The ljpeg_decode_yuv_scan function in libavcodec/mjpegdec.c in FFmpeg
    omitted certain width and height checks, which allowed remote
    attackers to cause a denial of service (out-of-bounds array access)
    or possibly have unspecified other impact via crafted MJPEG data. The
    issues have been fixed by adding a check for index to
    avcodec/mjpegdec.c in ljpeg_decode_yuv_scan() before using it, which
    fixes an out of array access.

CVE-2015-8217

    The ff_hevc_parse_sps function in libavcodec/hevc_ps.c did not
    validate the Chroma Format Indicator, which allowed remote attackers
    to cause a denial of service (out-of-bounds array access) or possibly
    have unspecified other impact via crafted High Efficiency Video
    Coding (HEVC) data. A check of chroma_format_idc in avcodec/hevc_ps.c
    has now been added to fix this out of array access.

CVE-2015-8363

    The jpeg2000_read_main_headers function in libavcodec/jpeg2000dec.c
    did not enforce uniqueness of the SIZ marker in a JPEG 2000 image,
    which allowed remote attackers to cause a denial of service
    (out-of-bounds heap-memory access) or possibly have unspecified other
    impact via a crafted image with two or more of these markers. In
    avcodec/jpeg2000dec.c a check for duplicate SIZ marker has been added
    to fix this.

CVE-2015-8364

    Integer overflow in the ff_ivi_init_planes function in
    libavcodec/ivi.c allowed remote attackers to cause a denial of
    service (out-of-bounds heap-memory access) or possibly have
    unspecified other impact via crafted image dimensions in Indeo Video
    Interactive data. A check of image dimensions has been added to the
    code (in avcodec/ivi.c) that fixes this integer overflow now.

CVE-2015-8661

    The h264_slice_header_init function in libavcodec/h264_slice.c did
    not validate the relationship between the number of threads and the
    number of slices, which allowed remote attackers to cause a denial of
    service (out-of-bounds array access) or possibly have unspecified
    other impact via crafted H.264 data. In avcodec/h264_slice.c now
    max_contexts gets limited when slice_context_count is initialized.
    This avoids an out of array access.

CVE-2015-8662

    The ff_dwt_decode function in libavcodec/jpeg2000dwt.c did not
    validate the number of decomposition levels before proceeding with
    Discrete Wavelet Transform decoding, which allowed remote attackers
    to cause a denial of service (out-of-bounds array access) or possibly
    have unspecified other impact via crafted JPEG 2000 data. In
    avcodec/jpeg2000dwt.c a check of ndeclevels has been added before
    calling dwt_decode*(). This fixes an out of array access.

CVE-2015-8663

    The ff_get_buffer function in libavcodec/utils.c preserved width and
    height values after a failure, which allowed remote attackers to
    cause a denial of service (out-of-bounds array access) or possibly
    have unspecified other impact via a crafted .mov file. Now,
    dimensions get cleared in ff_get_buffer() on failure, which fixes
    the cause for an out of array access.

CVE-2016-10190

    A heap-based buffer overflow in libavformat/http.c allowed remote web
    servers to execute arbitrary code via a negative chunk size in an
    HTTP response. In libavformat/http.c the length/offset-related
    variables have been made unsigned. This fix required inclusion of
    two other changes ported from ffmpeg upstream Git (commits 3668701f
    and 362c17e6).

CVE-2016-10191

    Another heap-based buffer overflow in libavformat/rtmppkt.c allowed
    remote attackers to execute arbitrary code by leveraging failure to
    check for RTMP packet size mismatches. By checking for packet size
    mismatched, this out of array access has been resolved.

DLA 1611-2:

Two more security issues have been corrected in the libav multimedia library. This is a follow-up announcement for DLA-1611-1.

CVE-2015-6823

The allocate_buffers function in libavcodec/alac.c did not initialize
certain context data, which allowed remote attackers to cause a
denial of service (segmentation violation) or possibly have
unspecified other impact via crafted Apple Lossless Audio Codec
(ALAC) data. This issues has now been addressed by clearing pointers
in avcodec/alac.c's allocate_buffers().

Other than stated in debian/changelog of upload 6:11.12-1~deb8u2,
this issue only now got fixed with upload of 6:11.12-1~deb8u3.

CVE-2015-6824

The sws_init_context function in libswscale/utils.c did not
initialize certain pixbuf data structures, which allowed remote
attackers to cause a denial of service (segmentation violation) or
possibly have unspecified other impact via crafted video data. In
swscale/utils.c now these pix buffers get cleared which fixes use of
uninitialized memory.

Other than stated in debian/changelog of upload 6:11.12-1~deb8u2,
this issue only now got fixed with upload of 6:11.12-1~deb8u3.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if ((res = isdpkgvuln(pkg:"libav-dbg", ver:"6:11.12-1~deb8u3", rls_regex:"DEB8\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libav-doc", ver:"6:11.12-1~deb8u3", rls_regex:"DEB8\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libav-tools", ver:"6:11.12-1~deb8u3", rls_regex:"DEB8\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libavcodec-dev", ver:"6:11.12-1~deb8u3", rls_regex:"DEB8\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libavcodec-extra", ver:"6:11.12-1~deb8u3", rls_regex:"DEB8\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libavcodec-extra-56", ver:"6:11.12-1~deb8u3", rls_regex:"DEB8\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libavcodec56", ver:"6:11.12-1~deb8u3", rls_regex:"DEB8\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libavdevice-dev", ver:"6:11.12-1~deb8u3", rls_regex:"DEB8\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libavdevice55", ver:"6:11.12-1~deb8u3", rls_regex:"DEB8\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libavfilter-dev", ver:"6:11.12-1~deb8u3", rls_regex:"DEB8\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libavfilter5", ver:"6:11.12-1~deb8u3", rls_regex:"DEB8\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libavformat-dev", ver:"6:11.12-1~deb8u3", rls_regex:"DEB8\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libavformat56", ver:"6:11.12-1~deb8u3", rls_regex:"DEB8\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libavresample-dev", ver:"6:11.12-1~deb8u3", rls_regex:"DEB8\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libavresample2", ver:"6:11.12-1~deb8u3", rls_regex:"DEB8\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libavutil-dev", ver:"6:11.12-1~deb8u3", rls_regex:"DEB8\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libavutil54", ver:"6:11.12-1~deb8u3", rls_regex:"DEB8\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libswscale-dev", ver:"6:11.12-1~deb8u3", rls_regex:"DEB8\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libswscale3", ver:"6:11.12-1~deb8u3", rls_regex:"DEB8\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}

if (report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}

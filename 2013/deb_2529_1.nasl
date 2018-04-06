# OpenVAS Vulnerability Test
# $Id: deb_2529_1.nasl 9353 2018-04-06 07:14:20Z cfischer $
# Auto-generated from advisory DSA 2529-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH http://greenbone.net
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

include("revisions-lib.inc");

tag_affected  = "python-django on Debian Linux";
tag_insight   = "Django is a high-level web application framework that loosely follows the
model-view-controller design pattern.";
tag_solution  = "For the stable distribution (squeeze), this problem has been fixed in
version 1.2.3-3+squeeze3.

For the unstable distribution (sid), this problem has been fixed in
version 1.4.1-1.

We recommend that you upgrade your python-django packages.";
tag_summary   = "Jeroen Dekkers and others reported several vulnerabilities in Django,
a Python Web framework. The Common Vulnerabilities and Exposures
project defines the following issues:

CVE-2012-3442Two functions do not validate the scheme of a redirect target,
which might allow remote attackers to conduct cross-site scripting
(XSS) attacks via a data: URL.

CVE-2012-3443The ImageField class completely decompresses image data during image
validation, which allows remote attackers to cause a denial of service
(memory consumption) by uploading an image file.

CVE-2012-3444The get_image_dimensions function in the image-handling functionality
uses a constant chunk size in all attempts to determine dimensions,
which allows remote attackers to cause a denial of service (process
or thread consumption) via a large TIFF image.";
tag_vuldetect = "This check tests the installed software version using the apt package manager.";

if(description)
{
    script_oid("1.3.6.1.4.1.25623.1.0.892529");
    script_version("$Revision: 9353 $");
    script_cve_id("CVE-2012-3444", "CVE-2012-3442", "CVE-2012-3443");
    script_name("Debian Security Advisory DSA 2529-1 (python-django - several vulnerabilities)");
    script_tag(name: "last_modification", value:"$Date: 2018-04-06 09:14:20 +0200 (Fri, 06 Apr 2018) $");
    script_tag(name:"creation_date", value:"2013-09-18 11:53:02 +0200 (Wed, 18 Sep 2013)");
    script_tag(name: "cvss_base", value:"5.0");
    script_tag(name: "cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

    script_xref(name: "URL", value: "http://www.debian.org/security/2012/dsa-2529.html");


    script_category(ACT_GATHER_INFO);

    script_copyright("Copyright (c) 2013 Greenbone Networks GmbH http://greenbone.net");
    script_family("Debian Local Security Checks");
    script_dependencies("gather-package-list.nasl");
    script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages");
    script_tag(name: "affected",  value: tag_affected);
    script_tag(name: "insight",   value: tag_insight);
#    script_tag(name: "impact",    value: tag_impact);
    script_tag(name: "solution",  value: tag_solution);
    script_tag(name: "summary",   value: tag_summary);
    script_tag(name: "vuldetect", value: tag_vuldetect);
    script_tag(name:"qod_type", value:"package");
    script_tag(name:"solution_type", value:"VendorFix");

    exit(0);
}

include("pkg-lib-deb.inc");

res = "";
report = "";
if ((res = isdpkgvuln(pkg:"python-django", ver:"1.2.3-3+squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"python-django-doc", ver:"1.2.3-3+squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}

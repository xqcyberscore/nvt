#
#VID f01292a0-db3c-11e1-a84b-00e0814cab4e
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from VID f01292a0-db3c-11e1-a84b-00e0814cab4e
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com
# Text descriptions are largely excerpted from the referenced
# advisories, and are Copyright (c) the respective author(s)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
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
tag_insight = "The following packages are affected:
   py26-django
   py27-django
   py26-django-devel
   py27-django-devel

CVE-2012-3442
The (1) django.http.HttpResponseRedirect and (2)
django.http.HttpResponsePermanentRedirect classes in Django before
1.3.2 and 1.4.x before 1.4.1 do not validate the scheme of a redirect
target, which might allow remote attackers to conduct cross-site
scripting (XSS) attacks via a data: URL.
CVE-2012-3443
The django.forms.ImageField class in the form system in Django before
1.3.2 and 1.4.x before 1.4.1 completely decompresses image data during
image validation, which allows remote attackers to cause a denial of
service (memory consumption) by uploading an image file.
CVE-2012-3444
The get_image_dimensions function in the image-handling functionality
in Django before 1.3.2 and 1.4.x before 1.4.1 uses a constant chunk
size in all attempts to determine dimensions, which allows remote
attackers to cause a denial of service (process or thread consumption)
via a large TIFF image.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

https://www.djangoproject.com/weblog/2012/jul/30/security-releases-issued/
http://www.vuxml.org/freebsd/f01292a0-db3c-11e1-a84b-00e0814cab4e.html";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory.";



if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.71513");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_cve_id("CVE-2012-3442", "CVE-2012-3443", "CVE-2012-3444");
 script_version("$Revision: 8671 $");
 script_tag(name:"last_modification", value:"$Date: 2018-02-05 17:38:48 +0100 (Mon, 05 Feb 2018) $");
 script_tag(name:"creation_date", value:"2012-08-10 03:22:17 -0400 (Fri, 10 Aug 2012)");
 script_name("FreeBSD Ports: py26-django, py27-django");


 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com");
 script_family("FreeBSD Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("ssh/login/freebsdrel", "login/SSH/success");
 script_tag(name : "insight" , value : tag_insight);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 script_tag(name:"qod_type", value:"package");
 script_tag(name:"solution_type", value:"VendorFix");
 exit(0);
}

#
# The script code starts here
#

include("pkg-lib-bsd.inc");
vuln = 0;
txt = "";
bver = portver(pkg:"py26-django");
if(!isnull(bver) && revcomp(a:bver, b:"1.4")>=0 && revcomp(a:bver, b:"1.4.1")<0) {
    txt += "Package py26-django version " + bver + " is installed which is known to be vulnerable.\n";
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"1.3")>=0 && revcomp(a:bver, b:"1.3.2")<0) {
    txt += "Package py26-django version " + bver + " is installed which is known to be vulnerable.\n";
    vuln = 1;
}
bver = portver(pkg:"py27-django");
if(!isnull(bver) && revcomp(a:bver, b:"1.4")>=0 && revcomp(a:bver, b:"1.4.1")<0) {
    txt += "Package py27-django version " + bver + " is installed which is known to be vulnerable.\n";
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"1.3")>=0 && revcomp(a:bver, b:"1.3.2")<0) {
    txt += "Package py27-django version " + bver + " is installed which is known to be vulnerable.\n";
    vuln = 1;
}
bver = portver(pkg:"py26-django-devel");
if(!isnull(bver) && revcomp(a:bver, b:"20120731,1")<0) {
    txt += "Package py26-django-devel version " + bver + " is installed which is known to be vulnerable.\n";
    vuln = 1;
}
bver = portver(pkg:"py27-django-devel");
if(!isnull(bver) && revcomp(a:bver, b:"20120731,1")<0) {
    txt += "Package py27-django-devel version " + bver + " is installed which is known to be vulnerable.\n";
    vuln = 1;
}

if(vuln) {
    security_message(data:string(txt ));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}

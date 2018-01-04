###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for rpmdevtools FEDORA-2012-13263
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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

include("revisions-lib.inc");
tag_affected = "rpmdevtools on Fedora 16";
tag_insight = "This package contains scripts and (X)Emacs support files to aid in
  development of RPM packages.
  rpmdev-setuptree    Create RPM build tree within user's home directory
  rpmdev-diff         Diff contents of two archives
  rpmdev-newspec      Creates new .spec from template
  rpmdev-rmdevelrpms  Find (and optionally remove) &quot;development&quot; RPMs
  rpmdev-checksig     Check package signatures using alternate RPM keyring
  rpminfo             Print information about executables and libraries
  rpmdev-md5/sha*     Display checksums of all files in an archive file
  rpmdev-vercmp       RPM version comparison checker
  spectool            Expand and download sources and patches in specfiles
  rpmdev-wipetree     Erase all files within dirs created by rpmdev-setuptree
  rpmdev-extract      Extract various archives, &quot;tar xvf&quot; style
  rpmdev-bumpspec     Bump revision in specfile
  ...and many more.";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.fedoraproject.org/pipermail/package-announce/2012-September/086159.html");
  script_id(864703);
  script_version("$Revision: 8273 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-03 07:29:19 +0100 (Wed, 03 Jan 2018) $");
  script_tag(name:"creation_date", value:"2012-09-17 16:39:40 +0530 (Mon, 17 Sep 2012)");
  script_cve_id("CVE-2012-3500");
  script_tag(name:"cvss_base", value:"1.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:N/I:P/A:N");
  script_xref(name: "FEDORA", value: "2012-13263");
  script_name("Fedora Update for rpmdevtools FEDORA-2012-13263");

  script_tag(name: "summary" , value: "Check for the Version of rpmdevtools");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms");
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("pkg-lib-rpm.inc");

release = get_kb_item("ssh/login/release");

res = "";
if(release == NULL){
  exit(0);
}

if(release == "FC16")
{

  if ((res = isrpmvuln(pkg:"rpmdevtools", rpm:"rpmdevtools~8.3~1.fc16", rls:"FC16")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}

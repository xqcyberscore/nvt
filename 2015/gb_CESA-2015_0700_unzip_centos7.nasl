###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for unzip CESA-2015:0700 centos7 
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.882143");
  script_version("$Revision: 6657 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-10 13:50:44 +0200 (Mon, 10 Jul 2017) $");
  script_tag(name:"creation_date", value:"2015-04-01 07:23:28 +0200 (Wed, 01 Apr 2015)");
  script_cve_id("CVE-2014-8139", "CVE-2014-8140", "CVE-2014-8141", "CVE-2014-9636");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("CentOS Update for unzip CESA-2015:0700 centos7 ");
  script_tag(name: "summary", value: "Check the version of unzip");
  script_tag(name: "vuldetect", value: "Get the installed version with the help of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "The unzip utility is used to list, test, or extract files from a
zip archive.

A buffer overflow was found in the way unzip uncompressed certain extra
fields of a file. A specially crafted Zip archive could cause unzip to
crash or, possibly, execute arbitrary code when the archive was tested with
unzip's '-t' option. (CVE-2014-9636)

A buffer overflow flaw was found in the way unzip computed the CRC32
checksum of certain extra fields of a file. A specially crafted Zip archive
could cause unzip to crash when the archive was tested with unzip's '-t'
option. (CVE-2014-8139)

An integer underflow flaw, leading to a buffer overflow, was found in the
way unzip uncompressed certain extra fields of a file. A specially crafted
Zip archive could cause unzip to crash when the archive was tested with
unzip's '-t' option. (CVE-2014-8140)

A buffer overflow flaw was found in the way unzip handled Zip64 files.
A specially crafted Zip archive could possibly cause unzip to crash when
the archive was uncompressed. (CVE-2014-8141)

Red Hat would like to thank oCERT for reporting the CVE-2014-8139,
CVE-2014-8140, and CVE-2014-8141 issues. oCERT acknowledges Michele
Spagnuolo of the Google Security Team as the original reporter of
these issues.

All unzip users are advised to upgrade to these updated packages, which
contain backported patches to correct these issues.
");
  script_tag(name: "affected", value: "unzip on CentOS 7");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");
  script_xref(name: "CESA", value: "2015:0700");
  script_xref(name: "URL" , value: "http://lists.centos.org/pipermail/centos-announce/2015-April/021042.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = get_kb_item("ssh/login/release");

res = "";
if(release == NULL){
  exit(0);
}

if(release == "CentOS7")
{

  if ((res = isrpmvuln(pkg:"unzip", rpm:"unzip~6.0~15.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
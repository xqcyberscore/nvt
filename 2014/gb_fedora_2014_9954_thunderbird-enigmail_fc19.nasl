###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for thunderbird-enigmail FEDORA-2014-9954
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.868176");
  script_version("$Revision: 2806 $");
  script_tag(name:"last_modification", value:"$Date: 2016-03-08 16:06:45 +0100 (Tue, 08 Mar 2016) $");
  script_tag(name:"creation_date", value:"2014-09-10 06:18:59 +0200 (Wed, 10 Sep 2014)");
  script_cve_id("CVE-2014-5369");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_name("Fedora Update for thunderbird-enigmail FEDORA-2014-9954");
  script_tag(name: "insight", value: "Enigmail is an extension to the mail client Mozilla Thunderbird
which allows users to access the authentication and encryption
features provided by GnuPG
");
  script_tag(name: "affected", value: "thunderbird-enigmail on Fedora 19");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name: "FEDORA", value: "2014-9954");
  script_xref(name: "URL" , value: "https://lists.fedoraproject.org/pipermail/package-announce/2014-September/137338.html");
  script_summary("Check for the Version of thunderbird-enigmail");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("HostDetails/OS/cpe:/o:fedoraproject:fedora", "login/SSH/success", "ssh/login/release");
exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = get_kb_item("ssh/login/release");

res = "";
if(release == NULL){
  exit(0);
}

if(release == "FC19")
{

  if ((res = isrpmvuln(pkg:"thunderbird-enigmail", rpm:"thunderbird-enigmail~1.7.2~1.fc19", rls:"FC19")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
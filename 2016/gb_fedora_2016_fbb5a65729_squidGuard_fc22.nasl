###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for squidGuard FEDORA-2016-fbb5a65729
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.808524");
  script_version("$Revision: 6631 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-10 08:36:10 +0200 (Mon, 10 Jul 2017) $");
  script_tag(name:"creation_date", value:"2016-07-02 06:39:06 +0200 (Sat, 02 Jul 2016)");
  script_cve_id("CVE-2015-8936");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for squidGuard FEDORA-2016-fbb5a65729");
  script_tag(name: "summary", value: "Check the version of squidGuard");

  script_tag(name: "vuldetect", value: "Get the installed version with the help
  of detect NVT and check if the version is vulnerable or not.");

  script_tag(name: "insight", value: "squidGuard can be used to
  - limit the web access for some users to a list of accepted/well known
    web servers and/or URLs only.
  - block access to some listed or blacklisted web servers and/or URLs
    for some users.
  - block access to URLs matching a list of regular expressions or words
    for some users.
  - enforce the use of domainnames/prohibit the use of IP address in
    URLs.
  - redirect blocked URLs to an 'intelligent' CGI based info page.
  - redirect unregistered user to a registration form.
  - redirect popular downloads like Netscape, MSIE etc. to local copies.
  - redirect banners to an empty GIF.
  - have different access rules based on time of day, day of the week,
    date etc.
  - have different rules for different user groups.
  - and much more..

  Neither squidGuard nor Squid can be used to
  - filter/censor/edit text inside documents
  - filter/censor/edit embeded scripting languages like JavaScript or
    VBscript inside HTML");

  script_tag(name: "affected", value: "squidGuard on Fedora 22");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "FEDORA", value: "2016-fbb5a65729");
  script_xref(name: "URL" , value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/FHL4KHU74SQ6GRXTOVKDL527QFSIQHJT");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = get_kb_item("ssh/login/release");

res = "";
if(release == NULL){
  exit(0);
}

if(release == "FC22")
{

  if ((res = isrpmvuln(pkg:"squidGuard", rpm:"squidGuard~1.4~26.fc22", rls:"FC22")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}

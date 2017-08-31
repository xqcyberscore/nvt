###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for munin FEDORA-2017-3776c9d747
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.872470");
  script_version("$Revision: 6634 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-10 09:32:24 +0200 (Mon, 10 Jul 2017) $");
  script_tag(name:"creation_date", value:"2017-03-11 05:50:29 +0100 (Sat, 11 Mar 2017)");
  script_cve_id("CVE-2017-6188");
  script_tag(name:"cvss_base", value:"1.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for munin FEDORA-2017-3776c9d747");
  script_tag(name: "summary", value: "Check the version of munin");
  script_tag(name: "vuldetect", value: "Get the installed version with the help of 
  detect NVT and check if the version is vulnerable or not."); 
  script_tag(name: "insight", value: "Munin is a highly flexible and powerful 
  solution used to create graphs of virtually everything imaginable throughout 
  your network, while still maintaining a rattling ease of installation and 
  configuration. This package contains the grapher/gatherer. You will only need 
  one instance of it in your network. It will periodically poll all the nodes in 
  your network it&#39 s aware of for data, which it in turn will use to create 
  graphs and HTML pages, suitable for viewing with your graphical web browser of 
  choice. Munin is written in Perl, and relies heavily on Tobi Oetiker&#39 s 
  excellent RRDtool. Creaete a munin web user after installing: htpasswd -bc 
  /etc/munin/munin-htpasswd MUNIN_WEB_USER PASSWORD "); 
  script_tag(name: "affected", value: "munin on Fedora 25");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "FEDORA", value: "2017-3776c9d747");
  script_xref(name: "URL" , value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/IZIUCTANYP6PVBJ3XX7XUK3CQIQGDQAV");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
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

if(release == "FC25")
{

  if ((res = isrpmvuln(pkg:"munin", rpm:"munin~2.0.30~5.fc25", rls:"FC25")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
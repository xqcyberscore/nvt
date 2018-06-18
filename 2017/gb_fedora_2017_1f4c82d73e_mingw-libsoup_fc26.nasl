###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2017_1f4c82d73e_mingw-libsoup_fc26.nasl 10231 2018-06-18 03:58:33Z ckuersteiner $
#
# Fedora Update for mingw-libsoup FEDORA-2017-1f4c82d73e
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
  script_oid("1.3.6.1.4.1.25623.1.0.873303");
  script_version("$Revision: 10231 $");
  script_tag(name:"last_modification", value:"$Date: 2018-06-18 05:58:33 +0200 (Mon, 18 Jun 2018) $");
  script_tag(name:"creation_date", value:"2017-08-25 08:19:36 +0200 (Fri, 25 Aug 2017)");
  script_cve_id("CVE-2017-2885");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for mingw-libsoup FEDORA-2017-1f4c82d73e");
  script_tag(name: "summary", value: "Check the version of mingw-libsoup");
  script_tag(name: "vuldetect", value: "Get the installed version with the help 
of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "Libsoup is an HTTP library implementation 
in C. It was originally part of a SOAP (Simple Object Access Protocol) 
implementation called Soup, but the SOAP and non-SOAP parts have now been split 
into separate packages.

libsoup uses the Glib main loop and is designed to work well with GTK
applications. This enables GNOME applications to access HTTP servers
on the network in a completely asynchronous fashion, very similar to
the Gtk+ programming model (a synchronous operation mode is also
supported for those who want it).

This is the MinGW build of Libsoup
");
  script_tag(name: "affected", value: "mingw-libsoup on Fedora 26");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "FEDORA", value: "2017-1f4c82d73e");
  script_xref(name: "URL" , value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/QHID2S2FQGHRN67ZKDIHFKMHLXJ3PMBP");
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

if(release == "FC26")
{

  if ((res = isrpmvuln(pkg:"mingw32-libsoup", rpm:"mingw32-libsoup~2.58.2~1.fc26", rls:"FC26")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}

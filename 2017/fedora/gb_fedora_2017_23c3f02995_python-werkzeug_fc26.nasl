###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2017_23c3f02995_python-werkzeug_fc26.nasl 7990 2017-12-05 07:08:14Z asteins $
#
# Fedora Update for python-werkzeug FEDORA-2017-23c3f02995
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
  script_oid("1.3.6.1.4.1.25623.1.0.873828");
  script_version("$Revision: 7990 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-05 08:08:14 +0100 (Tue, 05 Dec 2017) $");
  script_tag(name:"creation_date", value:"2017-12-04 18:48:24 +0530 (Mon, 04 Dec 2017)");
  script_cve_id("CVE-2016-10516");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for python-werkzeug FEDORA-2017-23c3f02995");
  script_tag(name: "summary", value: "Check the version of python-werkzeug");
  script_tag(name: "vuldetect", value: "Get the installed version with the help 
of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "Werkzeug
========

Werkzeug started as simple collection of various utilities for WSGI
applications and has become one of the most advanced WSGI utility
modules.  It includes a powerful debugger, full featured request and
response objects, HTTP utilities to handle entity tags, cache control
headers, HTTP dates, cookie handling, file uploads, a powerful URL
routing system and a bunch of community contributed addon modules.

Werkzeug is unicode aware and doesn&#39 t enforce a specific template
engine, database adapter or anything else.  It doesn&#39 t even enforce
a specific way of handling requests and leaves all that up to the
developer. It&#39 s most useful for end user applications which should work
on as many server environments as possible (such as blogs, wikis,
bulletin boards, etc.).
");
  script_tag(name: "affected", value: "python-werkzeug on Fedora 26");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "FEDORA", value: "2017-23c3f02995");
  script_xref(name: "URL" , value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/DVITKDXPYMQWU6HLMQ57RGBNRUDEM5ZY");
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

  if ((res = isrpmvuln(pkg:"python-werkzeug", rpm:"python-werkzeug~0.12.2~1.fc26", rls:"FC26")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}

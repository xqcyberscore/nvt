###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2018_2abadd4469_haproxy_fc28.nasl 13108 2019-01-17 07:34:03Z santu $
#
# Fedora Update for haproxy FEDORA-2018-2abadd4469
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2019 Greenbone Networks GmbH, http://www.greenbone.net
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.875403");
  script_version("$Revision: 13108 $");
  script_cve_id("CVE-2018-20103", "CVE-2018-20102");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2019-01-17 08:34:03 +0100 (Thu, 17 Jan 2019) $");
  script_tag(name:"creation_date", value:"2019-01-12 04:04:11 +0100 (Sat, 12 Jan 2019)");
  script_name("Fedora Update for haproxy FEDORA-2018-2abadd4469");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms");

  script_xref(name:"FEDORA", value:"2018-2abadd4469");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/3YR2YAKVQBVW3C2ZUEUPFK6TVYSOEQWE");

  script_tag(name:"summary", value:"The remote host is missing an update for the
 'haproxy' package(s) announced via the FEDORA-2018-2abadd4469 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is
  present on the target host.");

  script_tag(name:"insight", value:"HAProxy is a TCP/HTTP reverse proxy which is
  particularly suited for high availability environments. Indeed, it can:
 - route HTTP requests depending on statically assigned cookies
 - spread load among several servers while assuring server persistence
   through the use of HTTP cookies
 - switch to backup servers in the event a main one fails
 - accept connections to special ports dedicated to service monitoring
 - stop accepting connections without breaking existing ones
 - add, modify, and delete HTTP headers in both directions
 - block requests matching particular patterns
 - report detailed status to authenticated users from a URI
   intercepted from the application
");

  script_tag(name:"affected", value:"haproxy on Fedora 28.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "FC28")
{

  if ((res = isrpmvuln(pkg:"haproxy", rpm:"haproxy~1.8.15~1.fc28", rls:"FC28")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}

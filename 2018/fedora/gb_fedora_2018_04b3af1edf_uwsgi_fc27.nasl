###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2018_04b3af1edf_uwsgi_fc27.nasl 10597 2018-07-25 05:30:00Z cfischer $
#
# Fedora Update for uwsgi FEDORA-2018-04b3af1edf
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.874837");
  script_version("$Revision: 10597 $");
  script_tag(name:"last_modification", value:"$Date: 2018-07-25 07:30:00 +0200 (Wed, 25 Jul 2018) $");
  script_tag(name:"creation_date", value:"2018-07-21 06:05:30 +0200 (Sat, 21 Jul 2018)");
  script_cve_id("CVE-2018-6758", "CVE-2018-7490");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for uwsgi FEDORA-2018-04b3af1edf");
  script_tag(name:"summary", value:"Check the version of uwsgi");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present 
on the target host.");
  script_tag(name:"insight", value:"uWSGI is a fast (pure C), self-healing, 
developer/sysadmin-friendly application container server.  Born as a WSGI-only 
server, over time it has evolved in a complete stack for networked/clustered 
web applications, implementing message/object passing, caching, RPC and process 
management. It uses the uwsgi (all lowercase, already included by default in 
the Nginx and Cherokee releases) protocol for all the networking/interprocess
communications.  Can be run in preforking mode, threaded, asynchronous/evented 
and supports various form of green threads/co-routine (like uGreen and Fiber).  
Sysadmin will love it as it can be configured via command line, environment 
variables, xml, .ini and yaml files and via LDAP. Being fully modular can use 
tons of different technology on top of the same core.
");
  script_tag(name:"affected", value:"uwsgi on Fedora 27");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"FEDORA", value:"2018-04b3af1edf");
  script_xref(name:"URL" , value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/XRNUJCDU6EUVLTPG3WT6EIQO35XN3LHW");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
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

if(release == "FC27")
{

  if ((res = isrpmvuln(pkg:"uwsgi", rpm:"uwsgi~2.0.17.1~1.fc27", rls:"FC27")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}

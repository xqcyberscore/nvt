###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for python-celery FEDORA-2011-16539
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
tag_insight = "An open source asynchronous task queue/job queue based on
  distributed message passing. It is focused on real-time
  operation, but supports scheduling as well.

  The execution units, called tasks, are executed concurrently
  on one or more worker nodes using multiprocessing, Eventlet
  or gevent. Tasks can execute asynchronously (in the background)
  or synchronously (wait until ready).

  Celery is used in production systems to process millions of
  tasks a day.

  Celery is written in Python, but the protocol can be implemented
  in any language. It can also operate with other languages using
  webhooks.

  The recommended message broker is RabbitMQ, but limited support
  for Redis, Beanstalk, MongoDB, CouchDB and databases
  (using SQLAlchemy or the Django ORM) is also available.";

tag_affected = "python-celery on Fedora 16";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.fedoraproject.org/pipermail/package-announce/2011-December/070796.html");
  script_id(863777);
  script_version("$Revision: 8245 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-26 07:29:59 +0100 (Tue, 26 Dec 2017) $");
  script_tag(name:"creation_date", value:"2012-03-19 12:15:09 +0530 (Mon, 19 Mar 2012)");
  script_cve_id("CVE-2011-4356");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_xref(name: "FEDORA", value: "2011-16539");
  script_name("Fedora Update for python-celery FEDORA-2011-16539");

  script_tag(name: "summary" , value: "Check for the Version of python-celery");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms");
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "insight" , value : tag_insight);
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

  if ((res = isrpmvuln(pkg:"python-celery", rpm:"python-celery~2.2.8~1.fc16", rls:"FC16")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}

###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2018_5d6e80ab82_nekovm_fc28.nasl 11933 2018-10-17 07:09:44Z asteins $
#
# Fedora Update for nekovm FEDORA-2018-5d6e80ab82
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
  script_oid("1.3.6.1.4.1.25623.1.0.875179");
  script_version("$Revision: 11933 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-17 09:09:44 +0200 (Wed, 17 Oct 2018) $");
  script_tag(name:"creation_date", value:"2018-10-13 07:07:34 +0200 (Sat, 13 Oct 2018)");
  script_cve_id("CVE-2018-0497");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for nekovm FEDORA-2018-5d6e80ab82");
  script_tag(name:"summary", value:"Check the version of nekovm");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");
  script_tag(name:"insight", value:"Neko is a high-level dynamically typed
  programming language which can also be used as an embedded scripting language.
  It has been designed to provide a common run-time for several different
  languages. Neko is not only very easy to learn and use, but also has the
  flexibility of being able to extend the language with C libraries. You can even
  write generators from your own language to Neko and then use the Neko run-time
  to compile, run, and access existing libraries.

If you need to add a scripting language to your application, Neko
provides one of the best trade-offs available between simplicity,
extensibility and speed.

Neko allows the language designer to focus on design whilst reusing a
fast and well constructed run-time, as well as existing libraries for
accessing file system, network, databases, XML...

Neko has a compiler and virtual machine. The Virtual Machine is both
very lightweight and extremely well optimized so that it can run very
quickly. The VM can be easily embedded into any application and your
libraries are directly accessible using the C foreign function
interface.

The compiler converts a source .neko file into a byte-code .n file that
can be executed with the Virtual Machine. Although the compiler is
written in Neko itself, it is still very fast. You can use the
compiler as standalone command-line executable separated from the VM,
or as a Neko library to perform compile-and-run for interactive
languages.
");
  script_tag(name:"affected", value:"nekovm on Fedora 28");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"FEDORA", value:"2018-5d6e80ab82");
  script_xref(name:"URL" , value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/MYA4SSIXNC5CV3ZEAFZ4ERI24JOO3IBN");
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

if(release == "FC28")
{

  if ((res = isrpmvuln(pkg:"nekovm", rpm:"nekovm~2.2.0~8.fc28", rls:"FC28")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}

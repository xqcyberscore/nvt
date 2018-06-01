###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2018_9892225623_gifsicle_fc27.nasl 10046 2018-06-01 02:46:35Z ckuersteiner $
#
# Fedora Update for gifsicle FEDORA-2018-9892225623
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
  script_oid("1.3.6.1.4.1.25623.1.0.874626");
  script_version("$Revision: 10046 $");
  script_tag(name:"last_modification", value:"$Date: 2018-06-01 04:46:35 +0200 (Fri, 01 Jun 2018) $");
  script_tag(name:"creation_date", value:"2018-05-31 05:55:25 +0200 (Thu, 31 May 2018)");
  script_cve_id("CVE-2017-18120");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for gifsicle FEDORA-2018-9892225623");
  script_tag(name:"summary", value:"Check the version of gifsicle");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
on the target host.");
  script_tag(name:"insight", value:"Gifsicle is a command-line tool for creating,
editing, and getting information about GIF images and animations.

Some more gifsicle features:

    * Batch mode for changing GIFs in place.
    * Prints detailed information about GIFs, including comments.
    * Control over interlacing, comments, looping, transparency...
    * Creates well-behaved GIFs: removes redundant colors, only uses local
      color tables if it absolutely has to (local color tables waste space
      and can cause viewing artifacts), etc.
    * It can shrink colormaps and change images to use the Web-safe palette
      (or any colormap you choose).
    * It can optimize your animations! This stores only the changed portion
      of each frame, and can radically shrink your GIFs. You can also use
      transparency to make them even smaller. Gifsicle?s optimizer is pretty
      powerful, and usually reduces animations to within a couple bytes of
      the best commercial optimizers.
    * Unoptimizing animations, which makes them easier to edit.
    * A dumb-ass name.

One other program is included with gifsicle
and gifdiff compares two GIFs for identical visual appearance.
");
  script_tag(name:"affected", value:"gifsicle on Fedora 27");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"FEDORA", value:"2018-9892225623");
  script_xref(name:"URL" , value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/BGGLSEKCDM2OZ67XRI7KOASI4G7PRUX2");
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

  if ((res = isrpmvuln(pkg:"gifsicle", rpm:"gifsicle~1.91~1.fc27", rls:"FC27")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}

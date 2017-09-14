###############################################################################
# OpenVAS Include File
# $Id: gos_funcs.inc 7117 2017-09-13 14:28:38Z cfischer $
#
# Functions for supporting NVTs executed on a Greenbone OS (GOS)
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
# Jan Philipp Schulte <jan.schulte@greenbone.net>
# Adrian Steins <adrian.steins@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software
# Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301
# USA.
#
# $Revision: 7117 $
#
###############################################################################

# This function checks if the NVT calling this function is executed on a GOS
# It will return:
# TRUE  -> If executed on a GOS
# FALSE -> If not executed on a GOS or if a function needed for this check is missing
function executed_on_gos( )
{
  if ( ! defined_func( "vendor_version" ) ) return FALSE;

  if( vendor_version() =~ "^Greenbone OS" )
  {
    return TRUE;
  }
  else
  {
    return FALSE;
  }
}

# This function tries to detect the local GOS version of the NVT calling this function
# It will return:
# The version number as a string -> If executed on a GOS and it was possible to gather the version
# NULL -> If not executed on a GOS or it was not possible to gather the version
function get_local_gos_version( ) 
{
  local_var result;

  if ( ! executed_on_gos() )
  {
    return NULL;
  }
  else
  { 
    result = eregmatch( pattern:"([0-9.]+)$", string:vendor_version());
    return result[1];
  }
}
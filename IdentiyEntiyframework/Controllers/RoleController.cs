﻿using IdentiyEntiyframework.DataBase;
using IdentiyEntiyframework.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using NuGet.Packaging.Core;

namespace IdentiyEntiyframework.Controllers
{
    public class RoleController : Controller
    {
        
        private readonly ApplicationDBcontext  _db;
        private readonly UserManager<Applicationuser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;

        public RoleController(ApplicationDBcontext db,
            UserManager<Applicationuser> userManager,
            RoleManager<IdentityRole> roleManager)
        {
            _db = db;
            _userManager = userManager;
            _roleManager = roleManager;
        }
        public IActionResult Index()
        {
            
            var roles = _db.Roles.ToList();
           

            return View(roles);
        }
        [HttpGet]
        public IActionResult Upsert(string roleId)
        {
            if (String.IsNullOrEmpty(roleId))
            {
                //create
                return View();
            }
            else
            {
                //update
                var objFromDb = _db.Roles.FirstOrDefault(u => u.Id == roleId);
                return View(objFromDb);
            }
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Upsert(IdentityRole roleObj)
        {
            if (await _roleManager.RoleExistsAsync(roleObj.Name))
            {
                //error
                
            }
            if (String.IsNullOrEmpty(roleObj.NormalizedName))
            {
                await _roleManager.CreateAsync(new IdentityRole() { Name = roleObj.Name });
            }
            else
            {
                //update
                var objFromDb = _db.Roles.FirstOrDefault(u => u.Id == roleObj.Id);
                objFromDb.Name = roleObj.Name;
                objFromDb.NormalizedName = roleObj.Name.ToUpper();
                var result = await _roleManager.UpdateAsync(objFromDb);
                
            }
            return RedirectToAction(nameof(Index));
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Delete(string roleId)
        {
             var objFromDb = _db.Roles.FirstOrDefault(u => u.Id == roleId);
            if (objFromDb != null)
            {

                var userRolesForThisRole = _db.UserRoles.Where(u => u.RoleId == roleId).Count();
                if (userRolesForThisRole > 0)
                {
                    TempData[SD.Error] = "Cannot delete this role, since there are users assigned to this role.";
                    return RedirectToAction(nameof(Index));
                }

                var result = await _roleManager.DeleteAsync(objFromDb);
                TempData[SD.Success] = "Role deleted successfully";
            }
            else
            {
                TempData[SD.Error] = "Role not found.";
            }
            return RedirectToAction(nameof(Index));
        }

       
        }
    }


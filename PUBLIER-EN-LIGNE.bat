@echo off
rem ============================================================
rem  TRANSAC'IMMO - Publication en ligne en un double-clic
rem  Copie les fichiers de "mise en ligne" vers ton depot GitHub
rem  puis les pousse. Cloudflare redeploie tout seul (~1 min).
rem ============================================================
setlocal
set "ICI=%~dp0"
set "DEPOT=%ICI%depot"

where git >nul 2>nul
if errorlevel 1 (
  echo.
  echo  Git n'est pas installe. Telecharge-le ici puis relance ce script :
  echo  https://git-scm.com/download/win
  echo.
  pause
  exit /b 1
)

if not exist "%DEPOT%\.git" (
  echo Premiere utilisation : recuperation de ton depot GitHub...
  git clone https://github.com/dregnery/transac-immo "%DEPOT%"
  if errorlevel 1 (
    echo.
    echo  Echec : verifie ta connexion, ou connecte-toi quand Git le demande.
    pause
    exit /b 1
  )
)

echo Copie des fichiers a publier...
for %%F in (avis-de-valeur.html crm.html index.html worker.js wrangler.jsonc logo.jpg pige-marque-page.html dvf-hist.js dvf-points.js) do (
  if exist "%ICI%%%F" copy /y "%ICI%%%F" "%DEPOT%\%%F" >nul
)
if exist "%ICI%functions" xcopy /e /y /i "%ICI%functions" "%DEPOT%\functions" >nul

cd /d "%DEPOT%"
rem Identite Git (necessaire pour signer les publications)
git config user.name >nul 2>nul || git config user.name "David Regnery"
git config user.email >nul 2>nul || git config user.email "regnerydavid@gmail.com"
git add -A
git diff --cached --quiet
if not errorlevel 1 (
  echo Rien de nouveau a publier : le site est deja a jour.
  pause
  exit /b 0
)
git commit -m "Mise a jour du %date% %time%"
if errorlevel 1 (
  echo.
  echo  Echec de l'enregistrement — le message ci-dessus explique pourquoi.
  pause
  exit /b 1
)
echo Envoi vers GitHub...
git push
if errorlevel 1 (
  echo.
  echo  Echec de l'envoi. Si Git demande une connexion, une fenetre de
  echo  navigateur s'ouvre : connecte-toi a GitHub une seule fois,
  echo  puis relance ce script.
  pause
  exit /b 1
)
echo.
echo  ============================================
echo   Publie ! Cloudflare met le site a jour
echo   dans environ une minute.
echo  ============================================
echo.
pause

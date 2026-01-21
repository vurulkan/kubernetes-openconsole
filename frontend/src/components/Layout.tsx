import React from 'react';
import { AppBar, Box, Button, Divider, Drawer, List, ListItemButton, ListItemText, TextField, Toolbar, Typography } from '@mui/material';
import { useLocation, useNavigate } from 'react-router-dom';
import { User } from '../services/api';

const drawerWidth = 280;

type Props = {
  user: User;
  namespaces: string[];
  activeNamespace: string | null;
  onNamespaceChange: (value: string) => void;
  namespaceSearch?: string;
  onNamespaceSearchChange?: (value: string) => void;
  children: React.ReactNode;
};

const Layout: React.FC<Props> = ({
  user,
  namespaces,
  activeNamespace,
  onNamespaceChange,
  namespaceSearch = '',
  onNamespaceSearchChange,
  children
}) => {
  const navigate = useNavigate();
  const location = useLocation();
  const filteredNamespaces = namespaceSearch
    ? namespaces.filter((ns) => ns.toLowerCase().includes(namespaceSearch.trim().toLowerCase()))
    : namespaces;

  const handleLogout = () => {
    localStorage.removeItem('authToken');
    navigate('/login');
  };

  return (
    <Box display="flex">
      <AppBar position="fixed" sx={{ zIndex: 1201, background: '#fff', color: '#1a1a1a' }} elevation={1}>
        <Toolbar sx={{ display: 'flex', justifyContent: 'space-between' }}>
          <Typography variant="h6" fontWeight={600}>
            Kubernetes OpenConsole
          </Typography>
          <Box display="flex" gap={2} alignItems="center">
            <Typography variant="body2" color="text.secondary">
              {user.username}
            </Typography>
            {location.pathname.startsWith('/admin') && (
              <Button variant="outlined" size="small" onClick={() => navigate('/')}>
                Dashboard
              </Button>
            )}
            {user.isAdmin && (
              <Button variant="outlined" size="small" onClick={() => navigate('/admin')}>
                Admin
              </Button>
            )}
            <Button variant="contained" size="small" onClick={handleLogout}>
              Sign out
            </Button>
          </Box>
        </Toolbar>
      </AppBar>

      <Drawer
        variant="permanent"
        sx={{
          width: drawerWidth,
          flexShrink: 0,
          '& .MuiDrawer-paper': {
            width: drawerWidth,
            boxSizing: 'border-box',
            backgroundColor: '#0f1733',
            color: '#fff'
          }
        }}
      >
        <Toolbar />
        <Box sx={{ overflow: 'auto', px: 2, py: 3 }}>
          {onNamespaceSearchChange && (
            <TextField
              size="small"
              placeholder="Search namespaces"
              value={namespaceSearch}
              onChange={(event) => onNamespaceSearchChange(event.target.value)}
              fullWidth
              sx={{
                mb: 2,
                '& .MuiInputBase-root': { backgroundColor: '#111b3d', color: '#fff' },
                '& .MuiInputBase-input::placeholder': { color: '#9fb2ff', opacity: 1 },
                '& .MuiOutlinedInput-notchedOutline': { borderColor: '#1f2a4f' }
              }}
            />
          )}
          <Typography variant="caption" sx={{ textTransform: 'uppercase', color: '#9fb2ff' }}>
            Namespaces
          </Typography>
          <Divider sx={{ my: 1, borderColor: '#1f2a4f' }} />
          <List>
            {filteredNamespaces.map((ns) => (
              <ListItemButton
                key={ns}
                selected={activeNamespace === ns}
                onClick={() => onNamespaceChange(ns)}
                sx={{
                  borderRadius: 1,
                  '&.Mui-selected': { backgroundColor: '#1b2d6b' },
                  '&.Mui-selected:hover': { backgroundColor: '#1b2d6b' }
                }}
              >
                <ListItemText primary={ns} />
              </ListItemButton>
            ))}
          </List>
        </Box>
      </Drawer>

      <Box component="main" sx={{ flexGrow: 1, p: 3, minHeight: '100vh' }}>
        <Toolbar />
        {children}
      </Box>
    </Box>
  );
};

export default Layout;

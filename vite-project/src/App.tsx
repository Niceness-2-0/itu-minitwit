import {TimeLine} from './TimeLine.tsx'
import {WhatEver} from './WhatEver.tsx'
import './App.css'
import { BrowserRouter, Routes, Route } from 'react-router-dom';

function App() {

  return (
    <BrowserRouter>
		<Routes>
			<Route path="/" element={<TimeLine />} />
			<Route path="/whatever" element={<WhatEver />} />
		</Routes>
	</BrowserRouter>
  )
}

export default App
